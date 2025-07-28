require('dotenv').config();
const { Sequelize } = require('sequelize');

async function testSetup() {
  try {
    const sequelize = new Sequelize(process.env.DATABASE_URL);
    await sequelize.authenticate();
    console.log('✅ Database connection successful!');
    console.log('✅ Environment variables loaded');
    console.log('✅ Dependencies installed correctly');
    process.exit(0);
  } catch (error) {
    console.error('❌ Setup test failed:', error.message);
    process.exit(1);
  }
}

testSetup();