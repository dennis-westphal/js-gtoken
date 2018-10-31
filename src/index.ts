/**
 * Copyright 2018 Google LLC
 *
 * Distributed under MIT license.
 * See file LICENSE for detail or copy at https://opensource.org/licenses/MIT
 */

import axios from 'axios';
import * as jws from 'jws';
import * as mime from 'mime';
import * as querystring from 'querystring';

const GOOGLE_TOKEN_URL = 'https://www.googleapis.com/oauth2/v4/token';
const GOOGLE_REVOKE_TOKEN_URL =
    'https://accounts.google.com/o/oauth2/revoke?token=';

export interface Credentials {
  privateKey: string;
  clientEmail?: string;
}

export interface TokenData {
  refresh_token?: string;
  expires_in?: number;
  access_token?: string;
  token_type?: string;
  id_token?: string;
}

export interface TokenOptions {
  key?: string;
  email?: string;
  iss?: string;
  sub?: string;
  scope?: string|string[];
  additionalClaims?: {};
}

class ErrorWithCode extends Error {
  constructor(message: string, public code: string) {
    super(message);
  }
}

let getPem: ((filename: string) => Promise<string>)|undefined;

export class GoogleToken {
  token?: string|null = null;
  expiresAt?: number|null = null;
  key?: string;
  iss?: string;
  sub?: string;
  scope?: string;
  rawToken: TokenData|null = null;
  tokenExpires: number|null = null;
  email?: string;
  additionalClaims?: {};

  /**
   * Create a GoogleToken.
   *
   * @param options  Configuration object.
   */
  constructor(options?: TokenOptions) {
    this.configure(options);
  }

  /**
   * Returns whether the token has expired.
   *
   * @return true if the token has expired, false otherwise.
   */
  hasExpired() {
    const now = (new Date()).getTime();
    if (this.token && this.expiresAt) {
      return now >= this.expiresAt;
    } else {
      return true;
    }
  }

  /**
   * Returns a cached token or retrieves a new one from Google.
   *
   * @param callback The callback function.
   */
  getToken(): Promise<string|null|undefined>;
  getToken(callback: (err: Error|null, token?: string|null|undefined) => void):
      void;
  getToken(callback?: (err: Error|null, token?: string|null|undefined) => void):
      void|Promise<string|null|undefined> {
    if (callback) {
      this.getTokenAsync()
          .then(t => {
            callback(null, t);
          })
          .catch(callback);
      return;
    }
    return this.getTokenAsync();
  }

  private async getTokenAsync(): Promise<string|null|undefined> {
    if (!this.hasExpired()) {
      return Promise.resolve(this.token);
    }

    if (!this.key) {
      throw new Error('No key set.');
    }

    return this.requestToken();
  }

  private ensureEmail() {
    if (!this.iss) {
      throw new ErrorWithCode('email is required.', 'MISSING_CREDENTIALS');
    }
  }

  /**
   * Revoke the token if one is set.
   *
   * @param callback The callback function.
   */
  revokeToken(): Promise<void>;
  revokeToken(callback: (err?: Error) => void): void;
  revokeToken(callback?: (err?: Error) => void): void|Promise<void> {
    if (callback) {
      this.revokeTokenAsync().then(() => callback()).catch(callback);
      return;
    }
    return this.revokeTokenAsync();
  }

  private async revokeTokenAsync() {
    if (!this.token) {
      throw new Error('No token to revoke.');
    }
    return axios.get(GOOGLE_REVOKE_TOKEN_URL + this.token).then(r => {
      this.configure({
        email: this.iss,
        sub: this.sub,
        key: this.key,
        scope: this.scope,
        additionalClaims: this.additionalClaims,
      });
    });
  }


  /**
   * Configure the GoogleToken for re-use.
   * @param  {object} options Configuration object.
   */
  private configure(options: TokenOptions = {}) {
    this.key = options.key;
    this.token = this.expiresAt = this.rawToken = null;
    this.iss = options.email || options.iss;
    this.sub = options.sub;
    this.additionalClaims = options.additionalClaims;

    if (typeof options.scope === 'object') {
      this.scope = options.scope.join(' ');
    } else {
      this.scope = options.scope;
    }
  }

  /**
   * Request the token from Google.
   */
  private async requestToken(): Promise<string|null|undefined> {
    const iat = Math.floor(new Date().getTime() / 1000);
    const additionalClaims = this.additionalClaims || {};
    const payload = Object.assign(
        {
          iss: this.iss,
          scope: this.scope,
          aud: GOOGLE_TOKEN_URL,
          exp: iat + 3600,
          iat,
          sub: this.sub
        },
        additionalClaims);
    const signedJWT =
        jws.sign({header: {alg: 'RS256'}, payload, secret: this.key});
    return axios
        .post<TokenData>(
            GOOGLE_TOKEN_URL, querystring.stringify({
              grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer',
              assertion: signedJWT
            }),
            {headers: {'Content-Type': 'application/x-www-form-urlencoded'}})
        .then(r => {
          this.rawToken = r.data;
          this.token = r.data.access_token;
          this.expiresAt =
              (r.data.expires_in === null || r.data.expires_in === undefined) ?
              null :
              (iat + r.data.expires_in!) * 1000;
          return this.token;
        })
        .catch(e => {
          this.token = null;
          this.tokenExpires = null;
          const body = (e.response && e.response.data) ? e.response.data : {};
          let err = e;
          if (body.error) {
            const desc =
                body.error_description ? `: ${body.error_description}` : '';
            err = new Error(`${body.error}${desc}`);
          }
          throw err;
        });
  }
}
