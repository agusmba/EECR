'use strict';

angular.module('eecr2App.auth', ['eecr2App.constants', 'eecr2App.util', 'ngCookies', 'ui.router'])
  .config(function($httpProvider) {
    $httpProvider.interceptors.push('authInterceptor');
  });
