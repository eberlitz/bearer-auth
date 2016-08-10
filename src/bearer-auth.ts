export interface IAuthorizeOptions {
    username?: string;
    password?: string;
    clientId?: string;
    clientSecret?: string;
    authorizeUrl?: string;
    persistent?: boolean;
}

export interface IAuthorizationOptions {
    name?: string;
    url: string;
    authorizeUrl?: string;
    clientId?: string;
    /**
     * Função executada pelo interceptor quando não é possível obter um access_token através de um refresh_token.
     * Se função retornar uma promise e ela for resolvida então o interceptor tentará restaurar a requisição original.
     * Se a função retornar qualquer coisa ou uma promise rejeitada então a requisição original será retornada com erro.
     */
    resourceOwnerCredentialsFn?: (options: IAuthorizationOptions) => any | PromiseLike<any>;
    clientCredentialsFn?: (authService: AuthService, options: IAuthorizationOptions) => any | PromiseLike<any>;
    clientSecret?: string;
    persistent?: boolean;
}

export interface IAuthStorage {

    getItem(name: string): any;

    removeItem(name: string, isPersistent: boolean): void;

    setItem(name: string, value: any, isPersistent: boolean): void;
}

export interface IRequestConfig {
    headers?: {
        [requestType: string]: string | (() => string);
    }
}

function extend(...args: any[]) {
    var dst = args[0];
    for (var i = 1, ii = arguments.length; i < ii; i++) {
        var obj = arguments[i];
        if (obj) {
            var keys = Object.keys(obj);
            for (var j = 0, jj = keys.length; j < jj; j++) {
                var key = keys[j];
                dst[key] = obj[key];
            }
        }
    }
    return dst;
};

export class AuthService {
    public static TRATAR_401: string = 'authInterceptorRecoverFrom401';

    isPersistent: boolean;
    refresh_token: string;
    access_token: string;
    _pendingRequests: PromiseLike<any>[];

    static $q: any;
    static $http: any;
    static $storage: IAuthStorage;

    constructor(
        private options: IAuthorizationOptions
    ) {
        this.isPersistent = !!AuthService.$storage.getItem(`${options.name}-isPersistent`);
        this.options = <IAuthorizationOptions>extend(options, {
            clientCredentialsFn: (authService: AuthService, options: IAuthorizationOptions) => {
                // Função padrão para Self-Authorize
                return authService.authorize();
            }
        });
    }

    /**
     * Sign in using resource owner or client credentials
     */
    public authorize(options?: IAuthorizeOptions, config?: any) {
        //console.log(this.options.name, 'authorize', this.options);
        var me = this;
        options = <IAuthorizeOptions>extend({
            authorizeUrl: me.options.url + 'token'
        }, me.options, options);
        var deferred = AuthService.$q.defer();

        var data = {
            grant_type: options.username ? 'password' : 'client_credentials',
            username: options.username,
            password: options.password,
            // Opcionais
            client_id: options.clientId,
            client_secret: options.clientSecret
        };
        var body: string[] = [];
        for (var prop in data) {
            if ((<any>data)[prop] != null) {
                body.push(prop + '=' + encodeURIComponent((<any>data)[prop]));
            }
        }

        config = extend({
            ignoreAuthInterceptor: true
        }, config);

        if (!config.headers) {
            config.headers = {};
        }
        config.headers['Content-Type'] = 'application/x-www-form-urlencoded; charset=UTF-8';

        AuthService.$http.post(options.authorizeUrl, body.join('&'), config)
            .then(function (response: any) {
                me.setToken(response.data, !!options.persistent);
                deferred.resolve(response.data);
            }, function (response: any) {
                deferred.reject(response.data);
            });

        return deferred.promise;
    }

    /**
     * Removes authorization tokens from Storage.
     */
    removeToken() {
        var me = this;
        //var storage = me.isPersistent ? $window.localStorage : $window.sessionStorage;

        var propsToRemove = ['access_token', 'refresh_token', 'expires_at'];
        propsToRemove.map(function (prop) {
            AuthService.$storage.removeItem(me.options.name + '-' + prop, me.isPersistent);
        });
    }

    /**
     * Removes the authorization access token from Storage.
     */
    removeAccessToken() {
        var me = this;
        AuthService.$storage.removeItem(me.options.name + '-access_token', me.isPersistent);
        this.access_token = undefined;
    }

    /**
     * Returns true if an refresh token or access token is present in Storage and it is not expired, otherwise returns false.
     */
    isAuthenticated() {
        return this._hasRefreshToken() || this._hasAccessToken();
    }

    _hasRefreshToken() {
        this.refresh_token = this._getData('refresh_token');
        return !!this.refresh_token;
    }

    getRefreshToken() {
        if (this._hasRefreshToken()) {
            return this.refresh_token;
        };
        return null;
    }

    _hasAccessToken() {
        var me = this;
        var now = new Date().getTime();
        var expires_at = me._getData('expires_at');
        if (now < expires_at) {
            me.access_token = me._getData('access_token');
        } else {
            me.access_token = undefined;
        }
        return !!me.access_token;
    }

    _getData(propName: string) {
        var me = this;
        propName = me.options.name + '-' + propName;
        return AuthService.$storage.getItem(propName);
        // $window.sessionStorage.getItem(propName) || $window.localStorage.getItem(propName);
    }

    /**
     * Saves an authorization token to Storage.
     */
    setToken(tokenData: {
        access_token: string,
        refresh_token?: string,
        expires_in: string
    }, isPersistent: boolean) {
        var me = this;
        if (typeof me.isPersistent !== 'undefined' && me.isPersistent !== !!isPersistent) {
            me.removeToken();
        }
        me.isPersistent = !!isPersistent;
        // Sempre salva no localStorage
        AuthService.$storage.setItem(`${me.options.name}-isPersistent`, me.isPersistent, true);
        //var storage = me.isPersistent ? $window.localStorage : $window.sessionStorage;

        //Calculate exactly when the token will expire, then subtract
        //30sec to give ourselves a small buffer.
        var now = new Date().getTime();
        var expiresAt = now + parseInt(tokenData.expires_in, 10) * 1000 - 30000;

        var toStore = {
            access_token: tokenData.access_token,
            refresh_token: tokenData.refresh_token || me._getData('refresh_token'),
            expires_at: expiresAt
        };
        for (var prop in toStore) {
            AuthService.$storage.setItem(me.options.name + '-' + prop, (<any>toStore)[prop], me.isPersistent);
        }
        me.access_token = toStore.access_token;
        me.refresh_token = toStore.refresh_token;
    }

    _requestAccessToken() {
        var me = this;
        var deferred = AuthService.$q.defer();
        var options = extend({
            persistent: me.isPersistent
        }, {
                authorizeUrl: me.options.url + 'token'
            }, me.options);

        var data = {
            grant_type: 'refresh_token',
            refresh_token: me.refresh_token,
            // Opcionais
            client_id: options.clientId,
            client_secret: options.clientSecret
        };
        var body: string[] = [];
        for (var prop in data) {
            if ((<any>data)[prop] != null) {
                body.push(prop + '=' + encodeURIComponent((<any>data)[prop]));
            }
        }

        var refreshUrl = options.authorizeUrl;
        if (!me._hasPendingRequests()) {
            me._addPendingRequest(deferred);
            AuthService.$http.post(refreshUrl, body.join('&'), {
                ignoreAuthInterceptor: true,
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8'
                }
            }).then(function (response: any) {
                me.setToken(response.data, !!options.persistent);
                me._resolveAllPendingRequest(true, arguments);
            }, function () {
                me._resolveAllPendingRequest(false, arguments);
            });
        } else {
            me._addPendingRequest(deferred);
        }
        return deferred.promise;
    }

    private _requestCredentials() {
        var deferred = <any>AuthService.$q.defer();
        // deve resolver a promise para self-authorize
        // deve rejeitar a promise se não é possivel se auto-autorizar

        let isPromise = (object: any) => object && typeof object.then === 'function';

        // Verificar se a authorização é para resource_owner ou client
        if (this.options.resourceOwnerCredentialsFn) { // para ser resource_owner deve-se informar uma função
            let roCredentials = this.options.resourceOwnerCredentialsFn ? this.options.resourceOwnerCredentialsFn(this.options) : undefined;
            if (isPromise(roCredentials)) {
                roCredentials.then(() => deferred.resolve(), () => deferred.reject());
            } else {
                deferred.reject();
            }
        } else if (this.options.clientId && this.options.clientSecret) { // para client deve conter o id e o secret
            let cliCredentials = this.options.clientCredentialsFn ? this.options.clientCredentialsFn(this, this.options) : undefined;
            if (isPromise(cliCredentials)) {
                cliCredentials.then(() => deferred.resolve(), () => deferred.reject());
            } else {
                deferred.reject();
            }
        } else {
            deferred.reject();
        }

        return deferred.promise;
    }



    _authorizeRequest(httpConfig: IRequestConfig): IRequestConfig | PromiseLike<IRequestConfig> {
        var deferred = AuthService.$q.defer();

        let continueRequest = (access_token?: string) => {
            if (access_token) {
                httpConfig.headers['Authorization'] = 'Bearer ' + access_token;
            }
            deferred.resolve(httpConfig);
        };

        let isBadRefreshToken = (response: any) => {
            return response[0].status === 400 && response[0].data && response[0].data.error === 'invalid_grant';
        };

        // se accessTokenExisteEAindaNaoExpirou()
        if (this._hasAccessToken()) {
            //console.log("hasAccessToken");
            // marcaRequestParaRecuperaçãoEmEmCasoDeErro()
            (<any>httpConfig)[AuthService.TRATAR_401] = true;
            // addAccessTokenToHeader()
            // return continueRequest();
            continueRequest(this.access_token);
        } else {
            this.removeAccessToken(); //removendo para o caso de ter um expirado
            if (this._hasRefreshToken()) {
                // refreshTokens()
                this._requestAccessToken()
                    // .sucesso(()=>{
                    .then(() => {
                        // addAccessTokenToHeader()
                        // return continueRequest()
                        continueRequest(this.access_token);
                    },
                    // .falha((refreshRequestError)=>{
                    (response: any) => {
                        if (isBadRefreshToken(response)) {
                            this.removeToken();
                            // requestCredentials()
                            this._requestCredentials()
                                // deve resolver a promise para self-authorize
                                .then(() => {
                                    continueRequest(this.access_token);
                                },
                                // deve rejeitar a promise se não é possivel se auto-autorizar
                                () => {
                                    // Não tem solução então continua a request sem acrescentar o token
                                    continueRequest();
                                });
                        } else {
                            // pode ter sido erro de rede
                            continueRequest();
                        }
                    });
            } else {
                // requestCredentials()
                this._requestCredentials()
                    // deve resolver a promise para self-authorize
                    .then(() => {
                        continueRequest(this.access_token);
                    },
                    // deve rejeitar a promise se não é possivel se auto-autorizar
                    () => {
                        // Não tem solução então continua a request sem acrescentar o token
                        continueRequest();
                    });
            }
        }
        return deferred.promise;
    }

    _addPendingRequest(deferred: PromiseLike<any>) {
        var me = this;
        me._pendingRequests = me._pendingRequests || [];
        me._pendingRequests.push(deferred);
    }

    _hasPendingRequests() {
        var me = this;
        return (me._pendingRequests || []).length > 0;
    }

    _resolveAllPendingRequest(isSuccess: boolean, arglist: IArguments) {
        var me = this;
        (me._pendingRequests || []).map(function (deferred) {
            (<any>deferred)[isSuccess ? 'resolve' : 'reject'].call(deferred, arglist);
        });
        delete me._pendingRequests;
    }
}

export class AuthFactory {
    configs = {};

    public static $inject = [
        '$$authService'
    ];

    constructor(
        private AuthService: new (options: IAuthorizationOptions) => AuthService
    ) { }

    // ---------------------------------------------------------------
    configure(options: IAuthorizationOptions) {
        var name = options.name = options.name || 'default';
        if (name in this.configs) {
            throw 'name ' + name + ' is already taken!';
        }
        return (<any>this.configs)[name] = new this.AuthService(options);
    }

    get(name: string) {
        if (typeof name !== 'string') {
            throw 'Expected name to be a string! Found: ' + typeof name + '.';
        }
        var config = (<any>this.configs)[name];
        if (config) {
            return config;
        };
        return (<any>this.configs)['default'];
    }

    getByUrl(url: string) {
        if (typeof url !== 'string') {
            throw 'Expected url to be a string! Found: ' + typeof url + '.';
        }
        for (var u in this.configs) {
            var config = (<any>this.configs)[u];
            if (!!config.options.url && url.indexOf(config.options.url) === 0) {
                return config;
            };
        };
        return null;
    }
}

export default AuthService;