const dotenv = require('dotenv');
const express = require('express');
const http = require('http');
const logger = require('morgan');
const path = require('path');
const router = require('./routes/index');
const { auth } = require('express-openid-connect');




dotenv.load();




const app = express();




app.use(express.urlencoded({ extended: true }));
app.use(express.json());




app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'ejs');




app.use(logger('dev'));
app.use(express.static(path.join(__dirname, 'public')));
app.use(express.json());




const config = {
 authRequired: false,
 auth0Logout: true,
 secret: process.env.SECRET,
 baseURL: process.env.BASE_URL,
 clientID: process.env.CLIENT_ID,
 clientSecret: process.env.CLIENT_SECRET,
 //issuerBaseURL: process.env.API_AUDIENCE,
 authorizationParams: {
  response_type: 'code',
  scope: 'openid profile email phone read:authRocks write:authRocks delete:authRocks offline_access',
  audience: process.env.API_AUDIENCE,
  ui_locales: 'en'
 }
};




const port = process.env.PORT || 3000;
if (!config.baseURL && !process.env.BASE_URL && process.env.PORT && process.env.NODE_ENV !== 'production') {
 config.baseURL = `http://localhost:${port}`;
}




app.use(auth(config));




// Middleware to make the `user` object available for all views
app.use(function (req, res, next) {
 res.locals.user = req.oidc.user;
 next();
});




app.use('/', router);




// Catch 404 and forward to error handler
app.use(function (req, res, next) {
 const err = new Error('Not Found');
 err.status = 404;
 next(err);
});




// Error handlers
app.use(function (err, req, res, next) {
 res.status(err.status || 500);
 res.render('error', {
   message: err.message,
   error: process.env.NODE_ENV !== 'production' ? err : {}
 });
});




http.createServer(app)
 .listen(port, () => {
   console.log(`Listening on ${config.baseURL}`);
 });