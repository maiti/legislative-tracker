const { Sequelize } = require('sequelize');

const sequelize = new Sequelize(process.env.DATABASE_URL, {
  dialect: 'postgres',
  logging: process.env.NODE_ENV === 'development' ? console.log : false,
  pool: {
    max: 5,
    min: 0,
    acquire: 30000,
    idle: 10000
  }
});

// Import models
const User = require('./User')(sequelize, Sequelize.DataTypes);
const Bill = require('./Bill')(sequelize, Sequelize.DataTypes);
const Keyword = require('./Keyword')(sequelize, Sequelize.DataTypes);
const BillKeyword = require('./BillKeyword')(sequelize, Sequelize.DataTypes);
const UserWatchlist = require('./UserWatchlist')(sequelize, Sequelize.DataTypes);
const BillHistory = require('./BillHistory')(sequelize, Sequelize.DataTypes);

// Define associations
User.hasMany(UserWatchlist, { foreignKey: 'userId' });
UserWatchlist.belongsTo(User, { foreignKey: 'userId' });

Bill.hasMany(UserWatchlist, { foreignKey: 'billId' });
UserWatchlist.belongsTo(Bill, { foreignKey: 'billId' });

Bill.belongsToMany(Keyword, { 
  through: BillKeyword, 
  foreignKey: 'billId',
  otherKey: 'keywordId'
});
Keyword.belongsToMany(Bill, { 
  through: BillKeyword, 
  foreignKey: 'keywordId',
  otherKey: 'billId'
});

Bill.hasMany(BillHistory, { foreignKey: 'billId' });
BillHistory.belongsTo(Bill, { foreignKey: 'billId' });

module.exports = {
  sequelize,
  User,
  Bill,
  Keyword,
  BillKeyword,
  UserWatchlist,
  BillHistory
};