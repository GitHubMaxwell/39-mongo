import mongoose from 'mongoose';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';

const userSchema = new mongoose.Schema({
  username: {type: String, required: true},
  password: {type: String, required: true},
  // add the role / string
  role: {type: String, required: true, default : 'user', enum:['user','editor','admin']}
});



const capabilities = {
  user : ['read'],
  editor : ['read','update'],
  admin : ['read','update','delete','create']
};



userSchema.pre('save', function(next) {

  bcrypt.hash(this.password,10)
    .then( hashedPassword => {
      this.password = hashedPassword;
      next();
    })
    .catch( error => {
      throw error; 
    });

    
});

userSchema.statics.authenticate = function(auth) {
  let query = {username:auth.username};

  return this.findOne(query)
    .then(user => user && user.comparePassword(auth.password))
    .catch( error => {
      throw error; 
    });
};


userSchema.statics.authorize = function(token) {
  let user = jwt.verify(token, process.env.APP_SECRET || 'change');
  
  return this.findOne({_id: user.id})
    .then(user => {
      return user; 
    })
    .catch(err => {
      throw err; } );
};


// make sure i have the right bcrypt version (it needs v3 to work with Node v10)
userSchema.methods.comparePassword = function (password) {
  return bcrypt.compare(password, this.password)
    .then(response => {
      return response ? this : null;
    });
};

// add the capabilities to this token
userSchema.methods.generateToken = function() {
  let tokenData = {
    id : this._id,
    capabilities : capabilities[this.role]
  }
  return jwt.sign( tokenData, process.env.APP_SECRET || 'changeit');
};

export default mongoose.model('user', userSchema);