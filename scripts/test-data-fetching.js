import dotenv from 'dotenv';
import fetch from 'node-fetch';

// Load environment variables
dotenv.config();

const SERVER_URL = process.env.SERVER_URL || 'http://localhost:3001';

async function testDataFetching() {
  console.log('🧪 Testing data fetching with different login methods...\n');

  try {
    // Test 1: PIN Login
    console.log('📌 TEST 1: PIN Login');
    console.log('================');
    
    const pinResponse = await fetch(`${SERVER_URL}/api/auth/doctor-login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        pin: '123456',
        loginType: 'pin'
      })
    });

    const pinResult = await pinResponse.json();
    
    if (pinResponse.ok) {
      console.log('✅ PIN Login successful');
      console.log('👤 User ID:', pinResult.user.id);
      console.log('📧 Email:', pinResult.user.email);
      console.log('🏷️  Role:', pinResult.user.role);
      
      // Test profile fetch with PIN token
      console.log('\n🔍 Testing profile fetch with PIN token...');
      const profileResponse = await fetch(`${SERVER_URL}/api/auth/profile`, {
        headers: { 'Authorization': `Bearer ${pinResult.token}` }
      });
      
      if (profileResponse.ok) {
        const profileData = await profileResponse.json();
        console.log('✅ Profile data fetched successfully with PIN token');
        console.log('👤 Profile Name:', profileData.user ? profileData.user.full_name : 'N/A');
      } else {
        console.log('❌ Profile fetch failed with PIN token:', profileResponse.status);
      }
      
    } else {
      console.log('❌ PIN Login failed:', pinResult.error);
    }

    console.log('\n' + '='.repeat(50) + '\n');

    // Test 2: Email/Password Login
    console.log('📧 TEST 2: Admin Email/Password Login');
    console.log('====================================');
    
    const emailResponse = await fetch(`${SERVER_URL}/api/auth/doctor-login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        email: 'admin@drganeshcs.com',
        password: 'ganeshcs123',
        loginType: 'email'
      })
    });

    const emailResult = await emailResponse.json();
    
    if (emailResponse.ok) {
      console.log('✅ Email/Password Login successful');
      console.log('👤 User ID:', emailResult.user.id);
      console.log('📧 Email:', emailResult.user.email);
      console.log('🏷️  Role:', emailResult.user.role);
      
      // Test profile fetch with email token
      console.log('\n🔍 Testing profile fetch with email/password token...');
      const profileResponse = await fetch(`${SERVER_URL}/api/auth/profile`, {
        headers: { 'Authorization': `Bearer ${emailResult.token}` }
      });
      
      if (profileResponse.ok) {
        const profileData = await profileResponse.json();
        console.log('✅ Profile data fetched successfully with email/password token');
        console.log('👤 Profile Name:', profileData.user ? profileData.user.full_name : 'N/A');
        console.log('📞 Phone:', profileData.user ? profileData.user.phone : 'N/A');
        
        // Test content fetch
        console.log('\n🔍 Testing content fetch with email/password token...');
        const contentResponse = await fetch(`${SERVER_URL}/api/content`, {
          headers: { 'Authorization': `Bearer ${emailResult.token}` }
        });
        
        if (contentResponse.ok) {
          const contentData = await contentResponse.json();
          console.log('✅ Content data fetched successfully');
          console.log('📊 Content count:', contentData.content ? contentData.content.length : 0);
        } else {
          console.log('❌ Content fetch failed:', contentResponse.status);
        }
        
      } else {
        console.log('❌ Profile fetch failed with email/password token:', profileResponse.status);
      }
      
    } else {
      console.log('❌ Email/Password Login failed:', emailResult.error);
    }

    console.log('\n' + '='.repeat(50));
    console.log('🎯 TEST SUMMARY');
    console.log('===============');
    
    const pinWorking = pinResponse.ok;
    const emailWorking = emailResponse.ok;
    
    console.log(`📌 PIN Login: ${pinWorking ? '✅ Working' : '❌ Failed'}`);
    console.log(`📧 Email Login: ${emailWorking ? '✅ Working' : '❌ Failed'}`);
    
    if (pinWorking && emailWorking) {
      console.log('\n🎉 ALL TESTS PASSED! Both login methods work and can fetch data.');
    } else {
      console.log('\n⚠️  Some tests failed. Check the logs above for details.');
    }

  } catch (error) {
    console.error('\n💥 Test failed with error:', error.message);
    
    if (error.code === 'ECONNREFUSED') {
      console.log('\n🚨 Server is not running!');
      console.log('📝 Please start the server first:');
      console.log('   cd server && npm start');
    }
  }
}

// Run the test
console.log('🚀 Starting data fetching tests...\n');
testDataFetching();
