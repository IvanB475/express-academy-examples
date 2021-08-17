// Load environment variable from .env file if not supplied
const path = require('path');
require('dotenv').config({
  path: (typeof process.env.DOTENV_PATH !== 'undefined')
    ? path.resolve(process.cwd(), process.env.DOTENV_PATH)
    : path.resolve(process.cwd(), '.env'),
});

// --- Start ---
const express = require('express')
const morgan = require('morgan');
const fs = require('fs');
const { ERROR_PAGE_NOT_FOUND, ERROR_INTERNAL_SERVER_ERROR, errorDescriptor } = require('./errors');
// const publicKey = fs.readFileSync(process.env.PATH_TO_PUB_KEY);
const jwtExpress = require('express-jwt');
const jwt = require('jsonwebtoken');
const { customCORSAndAuthErrorMiddleware } = require('./utils/customMiddleware');
const _ = require('lodash');
const pretty = require('../src/utils/pretty');
const loadPrivateKey = require('../src/utils/loadPrivateKey');

const {
  certPrivate,
  certPublic,
} = loadPrivateKey();

const app = express()

app.use(morgan('combined'));


app.get('/', (req, res) => {
  res.send('Home Page')
})

app.get('/users', (req, res) => {
  res.send('Users Page!')
})

// route expects token passed in Authorization header in 'Bearer + token' format
app.get('/my-profile', jwtExpress({ secret: certPublic, algorithms: ['RS256'], requestProperty: 'auth'}), customCORSAndAuthErrorMiddleware,
(req, res, next) => {
  if (!req.auth) {
    return res.sendStatus(403);
  }
  next()
}, (req, res) => {
  res.status(200).json("That was a valid token!");
});

// route returns public key
app.get('/public', (req, res) => {
  res.status(200).json(certPublic);
})

// route creates a token for the user
app.get('/sign/:id', async (req, res) => {
  try { 
  const token = jwt.sign({
    userId: req.params.id,
  }, certPrivate, { algorithm: 'RS256'});
  res.send(token)
} catch(e) {
  throw new Error(e);
}
})

// next two error handling middlewares and it's comments are taken from jwt-middleware-final.js

// Handle 404 and 505
// The 404 Route (ALWAYS Keep this as the last route)
app.use((req, res, next) => {
  // Due awesome error handler we can just throw custom 404 error object.
  next(new Error(errorDescriptor(ERROR_PAGE_NOT_FOUND)));
});

// eslint-disable-next-line no-unused-vars
app.use((error, req, res, next) => {
  // Try to parse the error, if unable log it and set it to default one.
  let errorOut = {};
  let parsed = {};
  try {
    parsed = JSON.parse(error.message);
    errorOut = {
      ...parsed,
    };
  } catch (e) {
    console.log('[API - ERROR] Unknown error, unable to parse the error key, code and message:');
    console.error(error);
    errorOut.code = 500;
    errorOut.key = 'INTERNAL_SERVER_ERROR';
    errorOut.message = error.message;
  }

  // Audit the API errors
  // Get IP
  const ip = _.get(req, 'headers.x-forwarded-for') || _.get(req, 'connection.remoteAddress');

  // Send the response to the client
  res.setHeader('Content-Type', 'application/json');
  res.status(errorOut.code).send(pretty({
    error: 1,
    errors: [
      { ...errorOut },
    ],
    data: null,
  }));
});


const port = process.env.PORT;

app.listen(port, () => {
  console.log(`🚀  Server ready at ${port}`);
})
