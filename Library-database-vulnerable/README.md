# Library Database Management System - Web Frontend

A modern web-based frontend for the Library Database Management System, converted from C# Windows Forms to HTML, CSS, and JavaScript with a beautiful brownish library-themed color palette.

## Features

- 📚 **Manage Books** - Add, update, delete, and search books
- 👥 **Manage Members** - Handle library member records
- ✍️ **Manage Authors** - Maintain author information
- 🏢 **Manage Publishers** - Publisher records management (Admin only)
- 🔄 **Borrow/Return** - Process book borrowing and returning
- ✅ **Check Availability** - Search for available book copies
- 💰 **Manage Fines** - Track and manage fine payments
- 📊 **Reports** - View library statistics and reports
- 👤 **Manage Users** - System user administration (Admin only)

## Prerequisites

1. **Node.js** (v14 or higher) - [Download here](https://nodejs.org/)
2. **SQL Server** with your Library Database
3. **SQL Server Native Client** for Windows Authentication

## Database Setup

Make sure your SQL Server has the following tables created (as per your schema):
- Books
- Authors
- Publishers
- Genres
- Copies
- Members
- Borrowing
- Fines
- Users

### Create Users Table for Login

If you don't have a Users table, create it:

```sql
CREATE TABLE Users (
    UserID NVARCHAR(50) PRIMARY KEY,
    Username VARCHAR(50) NOT NULL,
    Password NVARCHAR(100) NOT NULL,
    Role VARCHAR(50) NOT NULL
);

-- Insert sample users
INSERT INTO Users VALUES ('U001', 'admin', 'admin123', 'Admin');
INSERT INTO Users VALUES ('U002', 'librarian', 'lib123', 'Librarian');
```

## Installation

1. **Navigate to the project folder:**
   ```powershell
   cd d:\Library-database
   ```

2. **Install dependencies:**
   ```powershell
   npm install
   ```

3. **Configure Database Connection:**
   
   Edit the `.env` file with your database settings:
   ```env
   # Database Configuration
   DB_SERVER=YOUR_SERVER_NAME\\SQLEXPRESS01
   DB_NAME=Library Database Management System
   DB_USER=
   DB_PASSWORD=
   
   # Set to 'true' for Windows Authentication
   DB_TRUSTED_CONNECTION=true
   
   # Server Configuration
   PORT=3000
   ```

4. **Start the server:**
   ```powershell
   npm start
   ```

5. **Open your browser:**
   Navigate to [http://localhost:3000](http://localhost:3000)

## Login Credentials

| Username | Password | Role |
|----------|----------|------|
| admin | admin123 | Admin |
| librarian | lib123 | Librarian |

## Role Permissions

### Admin
- Full access to all features
- Can manage Publishers
- Can manage Users
- Can perform backup/restore operations

### Librarian
- Can manage Books, Members, Authors
- Can process Borrow/Return
- Can check Availability
- Can manage Fines
- Can view Reports
- **Cannot** manage Publishers or Users

## Project Structure

```
Library-database/
├── package.json          # Node.js dependencies
├── server.js            # Express backend server with API routes
├── README.md            # This file
└── public/              # Frontend files
    ├── index.html       # Login page
    ├── dashboard.html   # Main dashboard
    ├── books.html       # Manage Books
    ├── members.html     # Manage Members
    ├── authors.html     # Manage Authors
    ├── publishers.html  # Manage Publishers (Admin)
    ├── users.html       # Manage Users (Admin)
    ├── borrowing.html   # Borrow/Return
    ├── availability.html # Check Availability
    ├── fines.html       # Manage Fines
    ├── reports.html     # Reports
    ├── css/
    │   └── styles.css   # Brownish library theme styles
    └── js/
        └── api.js       # API functions and utilities
```

## Color Theme

The application uses a beautiful brownish color palette inspired by classic libraries:

- **Primary Brown**: #5D4037
- **Accent Gold**: #D4A574
- **Background Cream**: #F5F0EB
- **Text Dark**: #3E2723

## API Endpoints

### Authentication
- `POST /api/login` - User login

### Books
- `GET /api/books` - Get all books
- `POST /api/books` - Add a book
- `PUT /api/books/:id` - Update a book
- `DELETE /api/books/:id` - Delete a book
- `GET /api/books/search/:title` - Search books

### Members
- `GET /api/members` - Get all members
- `POST /api/members` - Add a member
- `PUT /api/members/:id` - Update a member
- `DELETE /api/members/:id` - Delete a member

### Authors
- `GET /api/authors` - Get all authors
- `POST /api/authors` - Add an author
- `PUT /api/authors/:id` - Update an author
- `DELETE /api/authors/:id` - Delete an author

### Publishers
- `GET /api/publishers` - Get all publishers
- `POST /api/publishers` - Add a publisher
- `PUT /api/publishers/:id` - Update a publisher
- `DELETE /api/publishers/:id` - Delete a publisher

### Borrowing
- `GET /api/borrowing` - Get all borrowing records
- `POST /api/borrowing` - Borrow a book
- `PUT /api/borrowing/return/:id` - Return a book

### Fines
- `GET /api/fines` - Get all fines
- `POST /api/fines` - Add a fine
- `PUT /api/fines/:id` - Update a fine
- `DELETE /api/fines/:id` - Delete a fine

### Reports
- `GET /api/reports/most-borrowed` - Most borrowed books
- `GET /api/reports/overdue` - Overdue books
- `GET /api/reports/current-borrowed` - Currently borrowed books
- `GET /api/reports/inventory` - Books inventory summary

## Troubleshooting

### Connection Error
If you get a database connection error:
1. Make sure SQL Server is running
2. Verify the server name in `server.js`
3. Ensure the database name is correct
4. Check if SQL Server allows TCP/IP connections

### Windows Authentication Issues
If using Windows Authentication doesn't work, you may need:
1. Install `msnodesqlv8` driver:
   ```powershell
   npm install msnodesqlv8
   ```
2. Or use SQL Server Authentication by providing username and password in the config

### Port Already in Use
If port 3000 is already in use, change it in `server.js`:
```javascript
const PORT = 3001; // Change to any available port
```
## Author

Aimen Hafeez


## License

This project is for educational purposes.
