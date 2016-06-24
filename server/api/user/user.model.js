'use strict';

import crypto from 'crypto';
import config from '../../config/environment';
import mongoose from 'mongoose';
mongoose.Promise = require('bluebird');
import {Schema} from 'mongoose';

const authTypes = ['github', 'twitter', 'facebook', 'google'];

var UserSchema = new Schema({
  name: String,
  email: {
    type: String,
    lowercase: true,
    required: function() {
      if (authTypes.indexOf(this.provider) === -1) {
        return true;
      } else {
        return false;
      }
    }
  },
  role: {
    type: String,
    default: 'user'
  },
  password: {
    type: String,
    required: function() {
      if (authTypes.indexOf(this.provider) === -1) {
        return true;
      } else {
        return false;
      }
    }
  },
  provider: String,
  salt: String,
  facebook: {},
  twitter: {},
  google: {},
  github: {},

  nick: String,
  hash: String,
  stats: {
    copas: Number,
    h_copas: Number,
    h_temporada: Number,
    temporada_ant: Number,
    trofeos_leyenda: Number,
    victorias: Number,
    victorias_3c: Number,
    donaciones_tot: Number,
    nivel: Number,
    arena: Number,
  },
  clan_hash: String,
  telegram: String,
  avisos: {
  type: Number, default: 0,
  min: 0, max: 10
  },
  ban: {
  type: Boolean, default: 'false'
  },
  lista_negra: {
  type: Boolean, default: 'false'
  },
  verificado: {
  type: String, default: 'no',
  enum: ['no','espera','si']
  },
  cambio_clan: {
  tipo: {
  type: String, default: 'usuario',
  enum: ['usuario','sistema','colider']
  },
  activo: {
  type: Boolean, default: false,
  },
  mensaje: String
  },
  notas: [{
    usr: {
      type: String, default: 'sistema',
      enum: ['sistema','admin','colider']
    },
    tipo: {
      type: String, default: 'sistema',
      enum: config.tipoNota
    },
    fecha: {
      type: Date, default: Date.now
    },
    texto: String
  }],
  fecha_reg: {
      type: Date, default: Date.now
  },
  edad: Date,
  sexo: {
    type: String, default: 'x',
    enum: ['x','h','m']
  },
  grado: {
    type: String, default: 'invitado',
    enum: config.grado
  },
  avatar: String,
    favs_num: {
      type: Number, default: 0
  },
  favs: [{
    type: mongoose.Schema.Types.ObjectId, ref: 'User'
  }],
  premios: [{
    calidad: {
      type: String,
      enum: ['bronce','plata','oro']
    },
    fecha: {
      type: Date, default: Date.now
    },
    nombre: String
  }],
  indice_ved3: {
    v: {
      type: Number, default: 0
    },
    e: {
      type: Number, default: 0
    },
    d: {
      type: Number, default: 0
    },
    3: {
      type: Number, default: 0
    }
  },
  n_posts: {
    type: Number, default: 0
  },
  n_hilos: {
    type: Number, default: 0
  },
  privados: [{
    leido: {
      type: Boolean, default: false
    },
    fecha: {
      type: Date, default: Date.now
    },
    creador: String,
    creador_id: {
      type: mongoose.Schema.Types.ObjectId, ref: 'User'
    },
    mensaje: String
  }]
});

/**
 * Virtuals
 */

// Public profile information
UserSchema
  .virtual('profile')
  .get(function() {
    return {
      'name': this.name,
      'role': this.role
    };
  });

// Non-sensitive info we'll be putting in the token
UserSchema
  .virtual('token')
  .get(function() {
    return {
      '_id': this._id,
      'role': this.role
    };
  });

/**
 * Validations
 */

// Validate empty email
UserSchema
  .path('email')
  .validate(function(email) {
    if (authTypes.indexOf(this.provider) !== -1) {
      return true;
    }
    return email.length;
  }, 'Email cannot be blank');

// Validate empty password
UserSchema
  .path('password')
  .validate(function(password) {
    if (authTypes.indexOf(this.provider) !== -1) {
      return true;
    }
    return password.length;
  }, 'Password cannot be blank');

// Validate email is not taken
UserSchema
  .path('email')
  .validate(function(value, respond) {
    var self = this;
    if (authTypes.indexOf(this.provider) !== -1) {
      return respond(true);
    }
    return this.constructor.findOne({ email: value }).exec()
      .then(function(user) {
        if (user) {
          if (self.id === user.id) {
            return respond(true);
          }
          return respond(false);
        }
        return respond(true);
      })
      .catch(function(err) {
        throw err;
      });
  }, 'The specified email address is already in use.');

var validatePresenceOf = function(value) {
  return value && value.length;
};

/**
 * Pre-save hook
 */
UserSchema
  .pre('save', function(next) {
    // Handle new/update passwords
    if (!this.isModified('password')) {
      return next();
    }

    if (!validatePresenceOf(this.password)) {
      if (authTypes.indexOf(this.provider) === -1) {
        return next(new Error('Invalid password'));
      } else {
        return next();
      }
    }

    // Make salt with a callback
    this.makeSalt((saltErr, salt) => {
      if (saltErr) {
        return next(saltErr);
      }
      this.salt = salt;
      this.encryptPassword(this.password, (encryptErr, hashedPassword) => {
        if (encryptErr) {
          return next(encryptErr);
        }
        this.password = hashedPassword;
        next();
      });
    });
  });

/**
 * Methods
 */
UserSchema.methods = {
  /**
   * Authenticate - check if the passwords are the same
   *
   * @param {String} password
   * @param {Function} callback
   * @return {Boolean}
   * @api public
   */
  authenticate(password, callback) {
    if (!callback) {
      return this.password === this.encryptPassword(password);
    }

    this.encryptPassword(password, (err, pwdGen) => {
      if (err) {
        return callback(err);
      }

      if (this.password === pwdGen) {
        callback(null, true);
      } else {
        callback(null, false);
      }
    });
  },

  /**
   * Make salt
   *
   * @param {Number} byteSize Optional salt byte size, default to 16
   * @param {Function} callback
   * @return {String}
   * @api public
   */
  makeSalt(byteSize, callback) {
    var defaultByteSize = 16;

    if (typeof arguments[0] === 'function') {
      callback = arguments[0];
      byteSize = defaultByteSize;
    } else if (typeof arguments[1] === 'function') {
      callback = arguments[1];
    }

    if (!byteSize) {
      byteSize = defaultByteSize;
    }

    if (!callback) {
      return crypto.randomBytes(byteSize).toString('base64');
    }

    return crypto.randomBytes(byteSize, (err, salt) => {
      if (err) {
        callback(err);
      } else {
        callback(null, salt.toString('base64'));
      }
    });
  },

  /**
   * Encrypt password
   *
   * @param {String} password
   * @param {Function} callback
   * @return {String}
   * @api public
   */
  encryptPassword(password, callback) {
    if (!password || !this.salt) {
      if (!callback) {
        return null;
      } else {
        return callback('Missing password or salt');
      }
    }

    var defaultIterations = 10000;
    var defaultKeyLength = 64;
    var salt = new Buffer(this.salt, 'base64');

    if (!callback) {
      return crypto.pbkdf2Sync(password, salt, defaultIterations, defaultKeyLength)
                   .toString('base64');
    }

    return crypto.pbkdf2(password, salt, defaultIterations, defaultKeyLength, (err, key) => {
      if (err) {
        callback(err);
      } else {
        callback(null, key.toString('base64'));
      }
    });
  }
};

export default mongoose.model('User', UserSchema);
