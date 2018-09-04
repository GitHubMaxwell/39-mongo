import express from 'express';
// import morgan from 'morgan';
import cors from 'cors';
import authRouter from './auth/auth_router.js';
// import userRouter from './routes/router.js';

import errorHandler from './middleware/error.js';
import notFound from './middleware/404.js';
import badBod from './middleware/badBod.js';
import badBearer from './middleware/badBearer.js';

require('dotenv').config();

let app = express();

/////////////////////////// express middleware
app.use(cors());
// app.use(morgan('dev'));
app.use(express.json());
app.use(express.urlencoded({extended:true}));

/////////////////////////// routes
app.use(authRouter); // auth routes
// app.use(userRouter); // user routes


/////////////////////////// error handling middleware
app.use(badBearer); // 401 err
app.use(notFound); // 404 err
app.use(badBod); // 400 err
app.use(errorHandler); // 555 //change back to 500

/////////////////////////// server
let server = false;

module.exports = {
  start: (port) => {
    if(!server) {
      server = app.listen(port, (err) => {
        if(err) {throw err;}
        // console.log(`SERVER: ${server}`);
        console.log(`Server is running on port: ${port}`);
      });
    }
    else {
      console.log('Server is already running');
      //can i add the 'port' variable here for a better error
      //console.log(`Server is ALREADY up on port: ${server}`);
    }
  },

  stop: () => {
    server.close( () => {
      console.log('Server has been closed');
    });
  },
  server: app,

  /*
  ??? not in demo
  what does it do 
  import app from '../../src/app.js' in the auth.test.js from lab 16
  has to do with passing an instance of express over for mockgoose to use i believe
  */
};
