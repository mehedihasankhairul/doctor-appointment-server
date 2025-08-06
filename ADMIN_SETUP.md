# Admin User Setup Documentation

## 🎉 Admin User Created Successfully!

An admin user has been successfully created in your Eye Appointment system with the following credentials:

### 🔑 Login Credentials
- **Email**: `admin@drganeshcs.com`
- **Password**: `ganeshcs123`
- **Role**: `admin`

### 👤 User Details
- **Full Name**: Dr. Ganesh Admin
- **Phone**: +91-9876543210
- **Gender**: Male
- **Status**: Active ✅
- **Email Verified**: Yes ✅
- **Created**: 2025-08-06T18:33:25.465Z

## 🌐 How to Login

### Option 1: Doctor Portal (Recommended)
1. Visit: https://portal.drganeshcs.com
2. Click on "Doctor Portal" or navigate to the doctor login section
3. Choose "Email/Password" login type
4. Enter the credentials above

### Option 2: Local Development
1. Start the frontend: `npm run dev` (from the frontend directory)
2. Visit: http://localhost:5173
3. Click on "Doctor Portal" in the navigation
4. Choose "Email/Password" login type
5. Enter the credentials above

## 🔧 Technical Implementation

### Database Integration
- The admin user is stored in MongoDB with proper password hashing (bcrypt)
- The user has `admin` role with full system access
- Authentication is handled via JWT tokens

### Updated Authentication System
The `doctor-login` endpoint has been enhanced to:
- ✅ Check database for admin/doctor users first
- ✅ Support both PIN and email/password authentication
- ✅ Maintain backward compatibility with hardcoded doctor credentials
- ✅ Properly hash and verify passwords
- ✅ Update last login timestamps

### Security Features
- ✅ Secure password hashing with bcrypt (12 salt rounds)
- ✅ JWT token-based authentication
- ✅ Role-based access control (admin/doctor/patient)
- ✅ Proper error handling and validation

## 🛠️ Management Scripts

### Create Admin User
```bash
cd server
npm run create-admin
```

### Test Admin Login
```bash
cd server
npm run test-admin
```

### Manual Script Execution
```bash
cd server
node scripts/create-admin.js
node scripts/test-admin-login.js
```

## 📋 Available Scripts

The following npm scripts have been added to `package.json`:

- `npm run create-admin` - Creates/updates the admin user
- `npm run test-admin` - Tests admin login functionality

## 🔄 System Architecture

### Authentication Flow
1. User enters credentials in doctor portal
2. Frontend sends login request to `/api/auth/doctor-login`
3. Backend checks database for admin/doctor users
4. Password is verified using bcrypt
5. JWT token is generated and returned
6. Frontend stores token and redirects to portal dashboard

### Role Hierarchy
- **admin**: Full system access, content management, user management
- **doctor**: Content management, appointment viewing, patient data
- **patient**: Appointment booking, profile management

## 🚀 Next Steps

1. **Start the servers** if not already running:
   ```bash
   # Backend server
   cd server
   npm start
   
   # Frontend server (in another terminal)
   cd frontend
   npm run dev
   ```

2. **Test the login** using the test script:
   ```bash
   cd server
   npm run test-admin
   ```

3. **Access the portal** and verify functionality:
   - Navigate to doctor portal
   - Login with admin credentials
   - Verify access to content management features

## ⚠️ Security Notes

- The admin password is stored securely with bcrypt hashing
- JWT tokens have appropriate expiration times
- The system maintains backward compatibility with existing PIN-based access
- All admin operations are logged for audit purposes

## 🔍 Troubleshooting

### Common Issues

1. **"Invalid credentials" error**
   - Verify the email and password are exactly: `admin@drganeshcs.com` / `ganeshcs123`
   - Ensure the database connection is working
   - Check server logs for detailed error information

2. **Server connection issues**
   - Ensure MongoDB is running
   - Verify server is started with `npm start`
   - Check environment variables in `.env` file

3. **Database connection problems**
   - Verify MongoDB connection string in environment variables
   - Ensure proper network access to database
   - Check database permissions

### Log Locations
- Server logs: Console output when running `npm start`
- Database operations: MongoDB logs
- Authentication attempts: Server console with detailed error messages

---

✅ **Admin user setup is complete and ready for use!**
