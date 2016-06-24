(function(angular, undefined) {
'use strict';

angular.module('eecr2App.constants', [])

.constant('appConfig', {userRoles:['guest','user','admin'],tipoNota:['aviso','comentario','lista negra','cambio de clan','grado'],grado:['invitado','miembro','vip','colider','admin']})

;
})(angular);