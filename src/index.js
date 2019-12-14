const cookieParser = require('cookie-parser');
const jwt = require('jsonwebtoken');


require('dotenv').config({ path: '.env' });
const createServer = require('./createServer');
const db = require('./db');

const server = createServer();


// TODO Use express middlware to handle cookies (JWT)
server.express.use(cookieParser());
// TODO Use express middlware to populate current user
//decode JWT token
server.express.use((req, res, next)=>{
  const {token} = req.cookies;
  if(token) {
    //grab the userid from the token, verify that the token has not been tampered with by passing our secret.
    const {userId} = jwt.verify(token, process.env.APP_SECRET);
    //add the userid to the req object and pass it down the line.
    
    req.userId = userId;
   // console.log(userId);
  }

  next();
});
//pass the user to all requests if they are logged in
server.express.use(async(req, res, next)=>{
  if(!req.userId) return next();
  
  const user = await db.query.user(
    {where: { id: req.userId }}, '{id, permissions, email, name}')
    .catch(
    (errors)=>{
    // console.log('error');
   // console.log(errors);
   req.user=null;
        req.userId=null;
        }
    );
    if(user) {
      req.user = user;
    } else {
     // console.log('got the user');
    //  console.log(user);
      req.user=null;
      req.userId=null;
    }
      
    
  

    next();

});






server.start(
  {
    cors: {
      credentials: true,
      origin: process.env.FRONTEND_URL,
    },
  },
  deets => {
    console.log(`Server is now running on port http:/localhost:${deets.port}`);
  }
);
