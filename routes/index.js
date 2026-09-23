var router = require('express').Router();

const {
  requiresAuth
} = require('express-openid-connect');


// =====================================================
// HOME
// =====================================================

router.get('/', function (req, res, next) {
  res.render('index', {
    title: 'Sample Nodejs',
    isAuthenticated: req.oidc.isAuthenticated()
  });
});


// =====================================================
// PROFILE
// =====================================================

router.get('/profile', requiresAuth(), function (req, res) {

  const user = req.oidc.user || {};

  // IMPORTANT:
  // accessToken may not exist in the session.
  const accessToken = req.oidc.accessToken;

  let payload = null;

  if (accessToken && accessToken.access_token) {

    const access_token = accessToken.access_token;

    try {

      const base64Url = access_token.split('.')[1];

      if (base64Url) {

        const base64 = base64Url
          .replace(/-/g, '+')
          .replace(/_/g, '/');

        const padded = base64.padEnd(
          base64.length + ((4 - (base64.length % 4)) % 4),
          '='
        );

        payload = JSON.parse(
          Buffer.from(padded, 'base64').toString('utf8')
        );

      }

    } catch (error) {

      console.error('Unable to decode access token:', error);

      payload = {
        error: 'Unable to decode access token'
      };

    }

  } else {

    console.log('No access token available for this session.');

    payload = {
      message: 'No access token available'
    };

  }


  res.render('profile', {

    user: user,

    userProfile: JSON.stringify(
      user,
      null,
      2
    ),

    token: JSON.stringify(
      payload,
      null,
      2
    )

  });

});


// =====================================================
// ROCKS USER
// =====================================================

router.get('/rocksuser', requiresAuth(), (req, res) => {

  const accessToken = req.oidc.accessToken;

  if (!accessToken || !accessToken.access_token) {
    return res.status(401).send('No access token');
  }

  const access_token = accessToken.access_token;

  const base64Url = access_token.split('.')[1];

  if (!base64Url) {
    return res.status(400).send('Invalid JWT');
  }

  const base64 = base64Url
    .replace(/-/g, '+')
    .replace(/_/g, '/');

  const padded = base64.padEnd(
    base64.length + ((4 - (base64.length % 4)) % 4),
    '='
  );

  let payload;

  try {

    payload = JSON.parse(
      Buffer.from(padded, 'base64').toString('utf8')
    );

  } catch (error) {

    return res.status(400).send('Invalid token payload');

  }


  // Support both:
  //
  // "scopes": ["read:authRocks", "write:authRocks"]
  //
  // and:
  //
  // "scope": "openid profile write:authRocks"

  const scopes = Array.isArray(payload?.scopes)
    ? payload.scopes
    : typeof payload?.scope === 'string'
      ? payload.scope.split(/\s+/)
      : [];


  if (scopes.includes('write:authRocks')) {

    return res.render('rockuser');

  }


  return res
    .status(403)
    .send('Missing scope: write:authRocks');

});


// =====================================================
// ROLE CHECK
// =====================================================

function requireLucidRole(requiredRole) {

  return (req, res, next) => {

    const claims = req.oidc?.user || {};

    const roles =
      claims['https://lucid.com/roles'] || [];

    const hasRole =
      Array.isArray(roles) &&
      roles.includes(requiredRole);


    if (hasRole) {
      return next();
    }


    return res
      .status(403)
      .send('Forbidden');

  };

}


// =====================================================
// REQUIRED ROLE
// =====================================================

router.get(
  '/requiredrole',
  requiresAuth(),
  requireLucidRole('AuthRocks Access'),
  (req, res) => {

    res.send('Premium content');

  }
);


// =====================================================
// UPDATE ADDRESS
// =====================================================

router.get(
  '/update-address',
  requiresAuth(),
  (req, res) => {

    res.oidc.login({

      authorizationParams: {

        edit_address: 'true'

      },

      returnTo: '/profile'

    });

  }
);


// =====================================================
// UPDATE MFA Preference to True
// =====================================================

router.get(
  '/update-mfa-preference-to-true',
  requiresAuth(),
  (req, res) => {

    res.oidc.login({

      authorizationParams: {

        flagMfa: 'true'

      },

      returnTo: '/profile'

    });

  }
);

// =====================================================
// UPDATE MFA Preference to False
// =====================================================

router.get(
  '/update-mfa-preference-to-false',
  requiresAuth(),
  (req, res) => {

    res.oidc.login({

      authorizationParams: {

        flagMfa: 'false'

      },

      returnTo: '/profile'

    });

  }
);

// =====================================================
// UPDATE EMAIL
// =====================================================

router.get(
  '/update-email',
  requiresAuth(),
  (req, res) => {

    res.oidc.login({

      authorizationParams: {

        edit_email: 'true',

        acr_values:
          'http://schemas.openid.net/pape/policies/2007/06/multi-factor'

      },

      returnTo: '/profile'

    });

  }
);


// =====================================================
// UPDATE PHONE NUMBER
// =====================================================

router.get(
  '/update-phone-number',
  requiresAuth(),
  (req, res) => {

    res.oidc.login({

      authorizationParams: {

        edit_phone_number: 'true',

        acr_values:
          'http://schemas.openid.net/pape/policies/2007/06/multi-factor'

      },

      returnTo: '/profile'

    });

  }
);


// =====================================================
// UPDATE MFA
// =====================================================

router.get(
  '/update-mfa',
  requiresAuth(),
  (req, res) => {

    res.oidc.login({

      authorizationParams: {

        manage_mfa: 'true'

      },

      returnTo: '/profile'

    });

  }
);


// =====================================================
// NEW EMAIL - GENERATE OTP
// =====================================================

router.post(
  '/new-update-email',
  requiresAuth(),
  (req, res) => {

    console.log(
      'New email:',
      req.body.email
    );


    res.oidc.login({

      authorizationParams: {

        generateOTP: 'true',

        newEmail: req.body.email

      },

      returnTo: '/profile'

    });

  }
);


// =====================================================
// VERIFY OTP
// =====================================================

router.post(
  '/verifyotp',
  requiresAuth(),
  (req, res) => {

    console.log(
      'Email:',
      req.body.email
    );

    console.log(
      'OTP:',
      req.body.otp
    );


    res.oidc.login({

      authorizationParams: {

        verifyOTP: 'true',

        newEmail: req.body.email,

        otp: req.body.otp

      },

      returnTo: '/profile'

    });

  }
);


// =====================================================
// STEP-UP AUTH
// =====================================================

router.get(
  '/step-up-auth',
  requiresAuth(),
  (req, res) => {

    res.oidc.login({

      authorizationParams: {

        step_up_auth: 'true',

        prompt: false

      },

      returnTo: '/update-password'

    });

  }
);


// =====================================================
// UPDATE PASSWORD
// =====================================================

router.get(
  '/update-password',
  requiresAuth(),
  (req, res) => {

    res.oidc.login({

      authorizationParams: {

        edit_password: 'true',

        acr_values:
          'http://schemas.openid.net/pape/policies/2007/06/multi-factor'

      },

      returnTo: '/force-logout'

    });

  }
);


// =====================================================
// INVITE USER
// =====================================================

router.get(
  '/invite-user',
  requiresAuth(),
  (req, res) => {

    res.oidc.login({

      authorizationParams: {

        invite_user: 'true',

        prompt: false

      },

      returnTo: '/profile'

    });

  }
);


// =====================================================
// FORCE LOGOUT
// =====================================================

router.get(
  '/force-logout',
  requiresAuth(),
  (req, res) => {

    return res.oidc.logout({

      returnTo: 'http://localhost:3000'

    });

  }
);

// =====================================================
// test
// =====================================================

router.get(
  '/test',
  requiresAuth(),
  (req, res) => {

    res.oidc.login({

      authorizationParams: {

        flag: 'true'

      },

      returnTo: '/profile'

    });

  }
);


module.exports = router;