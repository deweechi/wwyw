const { forwardTo } = require('prisma-binding');
const { hasPermission } = require('../utils');

const Query = {
items: forwardTo('db'),
item: forwardTo('db'),
itemsConnection: forwardTo('db'),
me(parent, args, ctx, info) {
    if(!ctx.request.userId) {
        return null;
    }
    return ctx.db.query.user({
        where: { id: ctx.request.userId}
    }, info);
},
    async users(parent, args, ctx, info) {
        //check if the user is logged in.
        if(!ctx.request.userId) {
            throw new Error(`You do not have sufficient permissions to perform this operation`);
        }

        //check that the user is an admin
        hasPermission(ctx.request.user, ['ADMIN', 'PERMISSIONUPDATE']);

        //grab all the accounts
        return ctx.db.query.users({}, info);
    },
    async order(parent, args, ctx, info) {
        //is logged in?
        if(!ctx.request.userId) {
            throw new Error('Please log in to see your orders');
        }
        //who are you
        const order = await ctx.db.query.order({
            where: { id: args.id },
        }, info);
        if (!order) {
            throw new Error('This order either cannot be found or you do not have permission to view it.');
        }
        //check permiss
        const ownsOrder = order.user.id === ctx.request.userId;
        const hasAdminPermission = ctx.request.user.permissions.includes('ADMIN');
        if (!ownsOrder && !hasAdminPermission) {
            throw new Error('This order either cannot be found or you do not have permission to view it.');
        }
        //return the order
        return order;

    },
    async orders(parent, args, ctx, info) {
        const { userId } = ctx.request;
        if(!userId) {
            throw new Error('Please sign in to view your orders.');
        }
        return ctx.db.query.orders({
            where: {
                user: {id: userId}
            }
        }, info);
    }
    
  
};

module.exports = Query;
