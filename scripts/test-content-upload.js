import dotenv from 'dotenv';
import fetch from 'node-fetch';

// Load environment variables
dotenv.config();

const PRODUCTION_API_URL = 'https://api.drganeshcs.com/api';
const LOCAL_API_URL = 'http://localhost:3001/api';

async function testContentUpload() {
  console.log('🚀 Testing content upload functionality...\n');

  // Test both production and local (if available)
  const apis = [
    { name: 'Production', url: PRODUCTION_API_URL },
    { name: 'Local', url: LOCAL_API_URL }
  ];

  for (const api of apis) {
    console.log(`\n${'='.repeat(60)}`);
    console.log(`🌐 Testing ${api.name} API: ${api.url}`);
    console.log(`${'='.repeat(60)}\n`);

    try {
      // Step 1: Health check
      console.log('🏥 Step 1: Health Check');
      const healthResponse = await fetch(`${api.url}/health`, {
        method: 'GET'
      });
      
      if (healthResponse.ok) {
        console.log('✅ Health check passed');
      } else {
        console.log('❌ Health check failed:', healthResponse.status);
        continue; // Skip this API if health check fails
      }

      // Step 2: Test PIN login
      console.log('\n🔑 Step 2: Testing PIN Login');
      const pinLoginResponse = await fetch(`${api.url}/auth/doctor-login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          pin: '123456',
          loginType: 'pin'
        })
      });

      let pinToken = null;
      if (pinLoginResponse.ok) {
        const pinResult = await pinLoginResponse.json();
        pinToken = pinResult.token;
        console.log('✅ PIN login successful');
        console.log('👤 User ID:', pinResult.user.id);
        console.log('🏷️  Role:', pinResult.user.role);
      } else {
        console.log('❌ PIN login failed:', pinLoginResponse.status);
      }

      // Step 3: Test admin email login
      console.log('\n📧 Step 3: Testing Admin Email Login');
      const emailLoginResponse = await fetch(`${api.url}/auth/doctor-login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          email: 'admin@drganeshcs.com',
          password: 'ganeshcs123',
          loginType: 'email'
        })
      });

      let adminToken = null;
      if (emailLoginResponse.ok) {
        const emailResult = await emailLoginResponse.json();
        adminToken = emailResult.token;
        console.log('✅ Admin email login successful');
        console.log('👤 User ID:', emailResult.user.id);
        console.log('🏷️  Role:', emailResult.user.role);
      } else {
        const errorData = await emailLoginResponse.json();
        console.log('❌ Admin email login failed:', emailLoginResponse.status);
        console.log('💬 Error:', errorData.error);
      }

      // Step 4: Test content creation with PIN token
      if (pinToken) {
        console.log('\n📤 Step 4a: Testing content creation with PIN token');
        const pinContentResponse = await fetch(`${api.url}/content`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${pinToken}`
          },
          body: JSON.stringify({
            title: `PIN Test Content - ${new Date().toISOString()}`,
            description: 'Testing content creation with PIN authentication',
            content_url: 'https://www.youtube.com/watch?v=test-pin',
            content_type: 'youtube',
            category: 'test',
            tags: ['test', 'pin', 'automation'],
            is_published: true
          })
        });

        if (pinContentResponse.ok) {
          const pinContentResult = await pinContentResponse.json();
          console.log('✅ Content creation with PIN token successful');
          console.log('🆔 Content ID:', pinContentResult.content.id);
        } else {
          const errorData = await pinContentResponse.json();
          console.log('❌ Content creation with PIN token failed:', pinContentResponse.status);
          console.log('💬 Error:', errorData.error);
          console.log('📋 Details:', errorData.details || 'No additional details');
        }
      }

      // Step 5: Test content creation with admin token
      if (adminToken) {
        console.log('\n📤 Step 4b: Testing content creation with admin token');
        const adminContentResponse = await fetch(`${api.url}/content`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${adminToken}`
          },
          body: JSON.stringify({
            title: `Admin Test Content - ${new Date().toISOString()}`,
            description: 'Testing content creation with admin authentication',
            content_url: 'https://www.youtube.com/watch?v=test-admin',
            content_type: 'youtube',
            category: 'test',
            tags: ['test', 'admin', 'automation'],
            is_published: true
          })
        });

        if (adminContentResponse.ok) {
          const adminContentResult = await adminContentResponse.json();
          console.log('✅ Content creation with admin token successful');
          console.log('🆔 Content ID:', adminContentResult.content.id);
        } else {
          const errorData = await adminContentResponse.json();
          console.log('❌ Content creation with admin token failed:', adminContentResponse.status);
          console.log('💬 Error:', errorData.error);
          console.log('📋 Details:', errorData.details || 'No additional details');
        }
      }

      // Step 6: Test content fetching
      console.log('\n📥 Step 5: Testing content fetching');
      const contentResponse = await fetch(`${api.url}/content`, {
        method: 'GET'
      });

      if (contentResponse.ok) {
        const contentData = await contentResponse.json();
        console.log('✅ Content fetching successful');
        console.log('📊 Content count:', contentData.content?.length || 0);
      } else {
        console.log('❌ Content fetching failed:', contentResponse.status);
      }

    } catch (error) {
      console.log(`❌ ${api.name} API test failed with error:`, error.message);
      
      if (error.code === 'ECONNREFUSED') {
        console.log(`🚨 Cannot connect to ${api.name} server`);
      } else if (error.name === 'TypeError' && error.message.includes('fetch')) {
        console.log(`🌐 Network error connecting to ${api.name} API`);
      }
    }
  }

  console.log(`\n${'='.repeat(60)}`);
  console.log('🎯 TEST SUMMARY');
  console.log(`${'='.repeat(60)}`);
  console.log('✅ = Working');
  console.log('❌ = Failed');
  console.log('🚨 = Server not available');
  console.log('\nIf production content upload fails but local works,');
  console.log('the issue is likely that the production server needs');
  console.log('the updated authentication code deployed.');
  console.log('\nIf both fail with auth errors, check token generation.');
  console.log('If both fail with validation errors, check request format.');
}

// Run the test
testContentUpload();
