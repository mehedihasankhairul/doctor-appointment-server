import dotenv from 'dotenv';
import fetch from 'node-fetch';

// Load environment variables
dotenv.config();

const SERVER_URL = process.env.SERVER_URL || 'http://localhost:3001';

async function testAdminLogin() {
  try {
    console.log('🧪 Testing admin login functionality...\n');
    
    // Test admin login credentials
    const loginData = {
      email: 'admin@drganeshcs.com',
      password: 'ganeshcs123',
      loginType: 'email'
    };

    console.log('🔐 Testing admin login with:');
    console.log('   - Email:', loginData.email);
    console.log('   - Password:', '***********');
    console.log('   - Login Type:', loginData.loginType);
    console.log('\n📡 Sending request to:', `${SERVER_URL}/api/auth/doctor-login`);

    const response = await fetch(`${SERVER_URL}/api/auth/doctor-login`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(loginData)
    });

    const result = await response.json();

    if (response.ok) {
      console.log('\n✅ Admin login successful!');
      console.log('🎉 Response details:');
      console.log('   - Status:', response.status);
      console.log('   - Message:', result.message);
      console.log('   - User ID:', result.user.id);
      console.log('   - User Name:', result.user.name);
      console.log('   - User Email:', result.user.email);
      console.log('   - User Role:', result.user.role);
      console.log('   - Specialization:', result.user.specialization);
      console.log('   - Token Generated:', result.token ? 'Yes' : 'No');
      console.log('   - Token Preview:', result.token ? result.token.substring(0, 50) + '...' : 'None');
      
      console.log('\n🎯 Test Result: PASSED');
      console.log('🌐 You can now login to the doctor portal with these credentials.');
      
    } else {
      console.log('\n❌ Admin login failed!');
      console.log('🚨 Error details:');
      console.log('   - Status:', response.status);
      console.log('   - Error:', result.error || result.message);
      
      console.log('\n🎯 Test Result: FAILED');
    }

  } catch (error) {
    console.error('\n💥 Test failed with error:', error.message);
    
    if (error.code === 'ECONNREFUSED') {
      console.log('\n🚨 Server is not running!');
      console.log('📝 Please start the server first:');
      console.log('   cd /Users/mehedihasankhairul/Desktop/eye-appointment/server');
      console.log('   npm start');
    }
    
    console.log('\n🎯 Test Result: ERROR');
  }
}

// Run the test
console.log('🚀 Starting admin login test...\n');
testAdminLogin();
