const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { randomBytes } = require('crypto');
const { promisify } = require('util');
const { transport, makeAnEmail } = require('../mail');
const { hasPermission } = require('../utils');
const stripe = require('../stripe');
const storeUpload = require('../upload');



const Mutations = {
  async createItem(parent, args, ctx, info) {
    if(!ctx.request.userId) {
      throw new Error('You must be logged in to do that!');
    }
     
     const hasPermissions = ctx.request.user.permissions.some(permission=>['ADMIN', 'ITEMCREATE'].includes(permission));
     if(!hasPermissions) {
 
       throw new Error('Insufficient permission to perform this operation');
     }
     
    const item = await ctx.db.mutation.createItem(
      {
        data: {
          //creating relationship between item and user
          user:{
            connect: {
              id: ctx.request.userId,
            }
          },  
            ...args
      }
      },
      info
    );
    
    return item;
  },
  updateItem(parent, args, ctx, info) {
     //check permissions
     if(!ctx.request.userId) {throw new Error('You must be logged in!');}
     
     const hasPermissions = ctx.request.user.permissions.some(permission=>['ADMIN', 'ITEMUPDATE'].includes(permission));
     if(!hasPermissions) {
 
       throw new Error('Insufficient permission to perform this operation');
     }
     //proceed with update
    
    
    
    // first take a copy of the updates
    const updates = { ...args };
    // remove the ID from the updates
    //ID is fixed and not updatable
    delete updates.id;
    // run the update method
    return ctx.db.mutation.updateItem(
      {
        data: updates,
        where: {
          id: args.id,
        },
      },
      info
    );
  },
  async deleteItem(parent, args, ctx, info) {
    
    const where = { id: args.id };
    //find item
    const item = await ctx.db.query.item({ where }, `{ id title user { id }}`);
    //check permissions
    if(!ctx.request.userId) {throw new Error('You must be logged in!');}
    const itemOwner = item.user.id === ctx.request.userId;
    const hasPermissions = ctx.request.user.permissions.some(permission=>['ADMIN', 'ITEMDELETE'].includes(permission));
    if(!itemOwner && !hasPermissions) {

      throw new Error('Insufficient permission to perform this operation');
    }
    //delete item
    return ctx.db.mutation.deleteItem({ where }, info);
  },
  async signup(parent, args, ctx, info) {
    //change email to lowercase
    args.email = args.email.toLowerCase();
    //hash the password
    const password = await bcrypt.hash(args.password, 10);
    //Is this the first user???????
    const users = await ctx.db.query.users({ }, info);
    console.log(users.length);
    let permish = ['USER'];
    if(users.length<1) {
      permish.push('ADMIN');
    }

      //add user to the db
   
      const user = await ctx.db.mutation.createUser({
      data:{
        ...args, 
        password,
        permissions: { set: permish },
      },
    }, info);
    
   
  
    //create JWT token
    const token = jwt.sign( { userId: user.id }, process.env.APP_SECRET);
    //set the jwt as a cookie in the resp
    ctx.response.cookie('token', token, {
      httpOnly: true,
      maxAge: 1000*60*60*24*7, //7 day cookie
    });
    //return user 
    return user;
  },
  async signin(parent, {email, password}, ctx, info) {
    //is this user a member?
    const user = await ctx.db.query.user({ where: { email }});
    if(!user) {
      throw new Error(`The email (${email}) is not registerd for this site`);
    }
    //found the email, now check the password
    const valid = await bcrypt.compare(password, user.password);
    if(!valid) {
      throw new Error(`Invalid password for this account`);
    }
    //generate the JWT token
    const token = jwt.sign( { userId: user.id }, process.env.APP_SECRET);
    //set the cookie
    ctx.response.cookie('token', token, {
      httpOnly: true,
      maxAge: 1000*60*60*24*7, //7 day cookie
    });
    //return the user
    return user;

  },
  signout(parent, args, ctx, info) {
    ctx.response.clearCookie('token');
    return { message: 'User logged out'};
  },
  async requestReset(parent, args, ctx, info) {
    //check if this is a real user
    const user = await ctx.db.query.user({ where: { email: args.email }});
    if(!user) {
      throw new Error(`The email (${args.email}) is not registerd for this site`);
    }
    //set reset token and password expiry
    const resetToken = (await promisify(randomBytes)(20)).toString('hex');
    //set the tokenexpiry to expire in an hour
    const resetTokenExpiry = Date.now() + 3600000;
    const res = await ctx.db.mutation.updateUser({
      where: { email: args.email },
      data: { resetToken, resetTokenExpiry },
    });
    //console.log(res);
    //email the user
    const mailRes = await transport.sendMail({
      from: 'chip.deweese@gmail.com',
      to: user.email,
      subject: 'Password reset link',
      html: makeAnEmail(`You have requested to change your password. The following link will expire in an hour.
      \n\n <a href="${process.env.FRONTEND_URL}/reset?resetToken=${resetToken}">Click Here to Reset Password</a>`),
    });

    return { message: 'Password reset enabled'};
    
  },
  async resetPassword(parent, args, ctx, info) {
    
    //check if the password match
    if(args.password!== args.confirmPassword) {
      throw new Error('The passwords do not match');
      }
    //check if the reset token is valid

    //check if the toke in expired
    const [user] = await ctx.db.query.users(
      {where: {
        resetToken: args.resetToken,
        resetTokenExpiry_gte: Date.now() - 3600000,
      },     
    });
    if(!user) {
      throw new Error('This reset request is either not valid or has expired.');
    }
    //hash new password
    const password = await bcrypt.hash(args.password, 10);
    //save the password and remove the tokens
    const updatedUser = await ctx.db.mutation.updateUser({
      where: { email: user.email },
      data: { password,
      resetToken: null,
    resetTokenExpiry: null,},
    })
    //gen the jwt
    const token = jwt.sign( { userId: user.id }, process.env.APP_SECRET);
    //set the jwt cookie
    ctx.response.cookie('token', token, {
      httpOnly: true,
      maxAge: 100*60*60*24*7
    });
    //return the user
    return updatedUser;

  },
  async updatePermissions(parent, args, ctx, info) {
    //is user logged in?
    if(!ctx.request.userId) {throw new Error('You must be logged in!');}
    //who is doing the request
    const currentUser = await ctx.db.query.user({
      where: {
        id: ctx.request.userId,
      },
    }, info);
    //are they an admin?
    hasPermission(currentUser, ['ADMIN', 'PERMISSIONUPDATE']);
    //update the permissions
    return ctx.db.mutation.updateUser({
      data: {
        permissions: {
          set: args.permissions,
        }
      },
      where: {
        id: args.userId,
      },
    }, info);

  },
  async addToCart(parent, args, ctx, info) {
    //are they signed in?
    const { userId } = ctx.request;
    if(!userId) {
      throw new Error('You need to create an account and log in to add items to a cart. The Cart will expire in an hour.')
    }
    //query the users current cart
    const [existingCartItem] = await ctx.db.query.cartItems(
      {
        where: {
          user: { id: userId },
          item: { id: args.id },
        },
      });
    //check if the item is in the cart
    if (existingCartItem) {
      console.log('This item is already in their cart');
      return ctx.db.mutation.updateCartItem(
        {
          where: { id: existingCartItem.id },
          data: { quantity: 1 },
        },
        info
      );
    }


    //add new item
    return ctx.db.mutation.createCartItem({
      data: {
        user: {
          connect: { id: userId },
        },
        item: {
          connect: { id: args.id },
        },
      },
    },info);

  },
  async removeFromCart(parent, args, ctx, info) {
    //find the item
    const cartItem = await ctx.db.query.cartItem({
      where: {
        id: args.id,
      }
    }, '{id, user{id}}');
    //make sure we have the right cart
    if(!cartItem) throw new Error('No Cart item found to remove');
    if(cartItem.user.id !== ctx.request.userId) {
      throw new Error('This is not your cart!');
    }
    //remove the item
    return ctx.db.mutation.deleteCartItem({
      where: {
        id: args.id
      }
    }, info);
  },
  async createOrder(parent, args, ctx, info) {
    //query the current user
    const { userId } = ctx.request;
    if(!userId) throw new Error('You must be signed in to complete an order.');
    const user = await ctx.db.query.user({where: { id: userId}}, `
    {
      id
      name
      email
      cart {
        id
        quantity
        item {
          title
          price
          id
          description
          image
          largeImage
        }
      }
    }
    `);
    //recalculate the total
    //////////////////////////////////////////////////////////////
    //Need to check the quantity to ensure it is not more than 1
    //if it is then need to throw an error
    //also check if it is still available in the db
    ////////////////////////////////////////////////////////////
   /*  const orderItemQuantity = user.cart.map(cartItem => {
        const orderItemsQuantity = {
          ...cartItem.item,
          quantity: cartItem.quantity,
          user: { connect: {id:userId}},
        };
        
        return orderItemsQuantity;
      });
 */
  const itemCheckIds = user.cart.map(cartItem => {
    const itemCheck1 = {
      ...cartItem.item,
    
   };
  
  return itemCheck1.id;
});

async function checkItems(itemid){
const checkItem = await ctx.db.query.item({where: { id: itemid}},`
{
  id
  inventoryLevel
}`);
console.log(checkItem.inventoryLevel);
if(checkItem.inventoryLevel<1) throw new Error('One of your cart items is no longer available, please refresh and try again.');
return false;
} 

for(i=0;i<itemCheckIds.length;i++) {
  console.log(itemCheckIds[i]);
  await checkItems(itemCheckIds[i]);
}
  
 



      
    //console.log(itemCheckIds);
    const amount = user.cart.reduce((tally, cartItem)=>tally + cartItem.item.price*cartItem.quantity, 0);
   // console.log(`card will be charged: ${amount}`);
    //create the stripe charge

    /////////////////////////////////////////////////////
    //Need to add to the order, description, item etc
    /////////////////////////////////////////////////////
   // console.log("MetaData:::::");
    //console.log(args.token);
   // console.log(args.billing_address_city);
   // console.log(args);
    

    const charge = await stripe.charges.create({
      amount,
      currency: 'USD',
      source: args.token,
      description:"Handmade item purchased from WhatWoodYouWish.com.",
      metadata: {
        billing_address_city: args.billing_address_city,
        billing_address_country: args.billing_address_country,
        billing_address_country_code: args.billing_address_country_code,
        billing_address_line1: args.billing_address_line1,
        billing_address_state: args.billing_address_state,
        billing_address_zip: args.billing_address_zip,
        billing_name: args.billing_name,
        shipping_address_city: args.shipping_address_city,
        shipping_address_country: args.shipping_address_country,
        shipping_address_country_code: args.shipping_address_country_code,
        shipping_address_line1: args.shipping_address_line1,
        shipping_address_state: args.shipping_address_state,
        shipping_address_zip: args.shipping_address_zip,
        shipping_name: args.shipping_name,
      }
    });

   // console.log('charge...');
    //console.log(charge);

    //convert the cartitems to order items
    //create an array of all the order items

    const orderItemIds = user.cart.map(cartItem => {
      const orderItem1 = {
        ...cartItem.item,
        
      };
      
      return orderItem1.id;
    });

    const orderItems = user.cart.map(cartItem => {
      const orderItem = {
        ...cartItem.item,
        quantity: cartItem.quantity,
        user: { connect: {id:userId}},
      };
      delete orderItem.id;
      return orderItem;
    });
    
    //create the order
    const order = await ctx.db.mutation.createOrder({
      data: {
        total: charge.amount,
        charge: charge.id,
        billing_address_city: args.billing_address_city,
        billing_address_country: args.billing_address_country,
        billing_address_country_code: args.billing_address_country_code,
        billing_address_line1: args.billing_address_line1,
        billing_address_state: args.billing_address_state,
        billing_address_zip: args.billing_address_zip,
        billing_name: args.billing_name,
        shipping_address_city: args.shipping_address_city,
        shipping_address_country: args.shipping_address_country,
        shipping_address_country_code: args.shipping_address_country_code,
        shipping_address_line1: args.shipping_address_line1,
        shipping_address_state: args.shipping_address_state,
        shipping_address_zip: args.shipping_address_zip,
        shipping_name: args.shipping_name,
        items: { create:orderItems },
        user: {connect: {id: userId}},
      }
    })
    //clean up the cart
    const cartItemIds = user.cart.map(cartItem => cartItem.id);
    /////////////////////////////////////////////////////////////
    //updateManyItems(data: ItemUpdateManyMutationInput!, where: ItemWhereInput): BatchPayload!
    //updateManyItems(where:{id_in:cartItemIds} data: {quantity: 0} )
    //update the quantity of items in inventory
    ////////////////////////////////////////////////////////
    await ctx.db.mutation.updateManyItems(
      { data: {inventoryLevel: 0},
        where:{id_in:orderItemIds},
           });
    await ctx.db.mutation.deleteManyCartItems({
      where: {
        id_in: cartItemIds,
      }
    });
    //return the order to the client
    return order;


  },
  async uploadFile(parent, { file }, ctx, info) {
    const { stream, filename } = await file;
    await storeUpload({stream, filename});
    return true;

  }

};

module.exports = Mutations;
