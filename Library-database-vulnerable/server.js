const express = require("express");
const cors = require("cors");
const bodyParser = require("body-parser");
const path = require("path");
const auth = require("./auth-vulnerable.js");


require("dotenv").config();

const app = express();
const PORT = process.env.PORT || 5000;


// Middleware
app.use(cors());
app.use(bodyParser.json());
app.use(express.static(path.join(__dirname, "public")));

// SQL Server Configuration - Loaded from .env file
const useTrustedConnection = process.env.DB_TRUSTED_CONNECTION === "true";

// Use msnodesqlv8 for Windows Authentication, standard mssql for SQL Auth
const sql = useTrustedConnection
  ? require("mssql/msnodesqlv8")
  : require("mssql");

let dbConfig;

if (useTrustedConnection) {
  // Windows Authentication using ODBC connection string
  const server = process.env.DB_SERVER || "localhost";
  const database = process.env.DB_NAME || "Library Database Management System";
  dbConfig = {
    connectionString: `Driver={ODBC Driver 17 for SQL Server};Server=${server};Database=${database};Trusted_Connection=yes;`,
  };
} else {
  // SQL Server Authentication
  dbConfig = {
    user: process.env.DB_USER || "",
    password: process.env.DB_PASSWORD || "",
    server: process.env.DB_SERVER || "localhost",
    database: process.env.DB_NAME || "Library Database Management System",
    options: {
      encrypt: process.env.DB_ENCRYPT === "true",
      trustServerCertificate: true,
    },
  };
}

// Connection pool
let pool;

async function connectDB() {
  try {
    console.log("Attempting to connect to database...");
    console.log("Config:", JSON.stringify(dbConfig, null, 2));
    pool = await sql.connect(dbConfig);
    console.log("Connected to SQL Server database");
  } catch (err) {
    console.error("Database connection error:", err.message || err);
    if (err.originalError) {
      console.error(
        "Original error:",
        err.originalError.message || err.originalError,
      );
    }
  }
}

connectDB();
// ==================== AUTH ROUTES ====================
app.post("/api/login", async (req, res) => {
  try {
    const { username, password } = req.body;
    const result = await pool
      .request()
      .input("Username", sql.NVarChar, username)
      .input("Password", sql.NVarChar, password)
      .query(
        "SELECT Role FROM Users WHERE Username=@Username AND Password=@Password",
      );

    if (result.recordset.length > 0) {
      res.json({ success: true, role: result.recordset[0].Role });
    } else {
      res.json({ success: false, message: "Invalid credentials" });
    }
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ==================== BOOKS ROUTES ====================
app.get("/api/books", async (req, res) => {
  try {
    const result = await pool.request().query("SELECT * FROM Books");
    res.json(result.recordset);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post("/api/books", async (req, res) => {
  try {
    const {
      BookID,
      Title,
      ISBN,
      GenreID,
      AuthorID,
      PublisherID,
      YearPublished,
      Pages,
      Price,
    } = req.body;
    await pool
      .request()
      .input("BookID", sql.NVarChar, BookID)
      .input("Title", sql.NVarChar, Title)
      .input("ISBN", sql.NVarChar, ISBN)
      .input("GenreID", sql.NVarChar, GenreID)
      .input("AuthorID", sql.NVarChar, AuthorID)
      .input("PublisherID", sql.NVarChar, PublisherID)
      .input("YearPublished", sql.Int, YearPublished)
      .input("Pages", sql.Int, Pages)
      .input("Price", sql.Float, Price)
      .query(`INSERT INTO Books (BookID, Title, ISBN, GenreID, AuthorID, PublisherID, YearPublished, Pages, Price) 
                    VALUES (@BookID, @Title, @ISBN, @GenreID, @AuthorID, @PublisherID, @YearPublished, @Pages, @Price)`);
    res.json({ success: true, message: "Book added successfully!" });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.put("/api/books/:id", async (req, res) => {
  try {
    const {
      Title,
      ISBN,
      GenreID,
      AuthorID,
      PublisherID,
      YearPublished,
      Pages,
      Price,
    } = req.body;
    const result = await pool
      .request()
      .input("BookID", sql.NVarChar, req.params.id)
      .input("Title", sql.NVarChar, Title)
      .input("ISBN", sql.NVarChar, ISBN)
      .input("GenreID", sql.NVarChar, GenreID)
      .input("AuthorID", sql.NVarChar, AuthorID)
      .input("PublisherID", sql.NVarChar, PublisherID)
      .input("YearPublished", sql.Int, YearPublished)
      .input("Pages", sql.Int, Pages)
      .input("Price", sql.Float, Price)
      .query(`UPDATE Books SET Title=@Title, ISBN=@ISBN, GenreID=@GenreID, AuthorID=@AuthorID, 
                    PublisherID=@PublisherID, YearPublished=@YearPublished, Pages=@Pages, Price=@Price 
                    WHERE BookID=@BookID`);
    res.json({
      success: result.rowsAffected[0] > 0,
      message:
        result.rowsAffected[0] > 0
          ? "Book updated successfully!"
          : "Book not found",
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.delete("/api/books/:id", async (req, res) => {
  try {
    const result = await pool
      .request()
      .input("BookID", sql.NVarChar, req.params.id)
      .query("DELETE FROM Books WHERE BookID=@BookID");
    res.json({
      success: result.rowsAffected[0] > 0,
      message:
        result.rowsAffected[0] > 0
          ? "Book deleted successfully!"
          : "Book not found",
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get("/api/books/search/:title", async (req, res) => {
  try {
    const result = await pool
      .request()
      .input("Title", sql.NVarChar, "%" + req.params.title + "%")
      .query("SELECT * FROM Books WHERE Title LIKE @Title");
    res.json(result.recordset);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ==================== MEMBERS ROUTES ====================
app.get("/api/members", async (req, res) => {
  try {
    const result = await pool.request().query("SELECT * FROM Members");
    res.json(result.recordset);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post("/api/members", async (req, res) => {
  try {
    const { MemberID, FullName, Email, Phone, Address, MembershipDate } =
      req.body;
    await pool
      .request()
      .input("MemberID", sql.NVarChar, MemberID)
      .input("FullName", sql.NVarChar, FullName)
      .input("Email", sql.NVarChar, Email)
      .input("Phone", sql.NVarChar, Phone)
      .input("Address", sql.NVarChar, Address)
      .input("MembershipDate", sql.Date, MembershipDate)
      .query(`INSERT INTO Members (MemberID, FullName, Email, Phone, Address, MembershipDate) 
                    VALUES (@MemberID, @FullName, @Email, @Phone, @Address, @MembershipDate)`);
    res.json({ success: true, message: "Member added successfully!" });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.put("/api/members/:id", async (req, res) => {
  try {
    const { Phone, Email, Address } = req.body;
    const result = await pool
      .request()
      .input("MemberID", sql.NVarChar, req.params.id)
      .input("Phone", sql.NVarChar, Phone)
      .input("Email", sql.NVarChar, Email)
      .input("Address", sql.NVarChar, Address)
      .query(
        "UPDATE Members SET Phone=@Phone, Email=@Email, Address=@Address WHERE MemberID=@MemberID",
      );
    res.json({
      success: result.rowsAffected[0] > 0,
      message:
        result.rowsAffected[0] > 0
          ? "Member updated successfully!"
          : "Member not found",
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.delete("/api/members/:id", async (req, res) => {
  try {
    const result = await pool
      .request()
      .input("MemberID", sql.NVarChar, req.params.id)
      .query("DELETE FROM Members WHERE MemberID=@MemberID");
    res.json({
      success: result.rowsAffected[0] > 0,
      message:
        result.rowsAffected[0] > 0
          ? "Member deleted successfully!"
          : "Member not found",
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get("/api/members/search/:name", async (req, res) => {
  try {
    const result = await pool
      .request()
      .input("Name", sql.NVarChar, "%" + req.params.name + "%")
      .query("SELECT * FROM Members WHERE FullName LIKE @Name");
    res.json(result.recordset);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ========================================================================================
// ================ The following apis are the auth-vulnerable ============================
// ========================================================================================

app.post("/api/auth/login-jwt-vulnerable", async (req, res) => {
  try {
    const { username, password } = req.body;
    const result = await pool
      .request()
      .input("Username", sql.NVarChar, username)
      .input("Password", sql.NVarChar, password)
      .query(
        "SELECT UserID, Role FROM Users WHERE Username=@Username AND Password=@Password",
      );

    if (result.recordset.length > 0) {
      const user = result.recordset[0];
      const token = auth.generateVulnerableJWT(
        user.UserID,
        username,
        user.Role,
      );
      res.json({
        success: true,
        token: token,
        role: user.Role,
        message: "Vulnerable JWT token generated",
      });
    } else {
      res.json({ success: false, message: "Invalid credentials" });
    }
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// PROTECTED ENDPOINTS - Require vulnerable JWT
app.get(
  "/api/books-protected",
  auth.vulnerableJWTMiddleware,
  async (req, res) => {
    try {
      // Optional: Log the request
      console.log(
        `[JWT] GET /api/books-protected by user: ${req.user.username}, role: ${req.user.role}`,
      );
      const result = await pool.request().query("SELECT * FROM Books");
      res.json(result.recordset);
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  },
);

app.post(
  "/api/books-protected",
  auth.vulnerableJWTMiddleware,
  async (req, res) => {
    try {
      // Verify admin role (but this is in the JWT which can be forged!)
      if (req.user.role !== "Admin") {
        return res.status(403).json({ error: "Admin access required" });
      }

      const {
        BookID,
        Title,
        ISBN,
        GenreID,
        AuthorID,
        PublisherID,
        YearPublished,
        Pages,
        Price,
      } = req.body;
      await pool
        .request()
        .input("BookID", sql.NVarChar, BookID)
        .input("Title", sql.NVarChar, Title)
        .input("ISBN", sql.NVarChar, ISBN)
        .input("GenreID", sql.NVarChar, GenreID)
        .input("AuthorID", sql.NVarChar, AuthorID)
        .input("PublisherID", sql.NVarChar, PublisherID)
        .input("YearPublished", sql.Int, YearPublished)
        .input("Pages", sql.Int, Pages)
        .input("Price", sql.Float, Price)
        .query(`INSERT INTO Books (BookID, Title, ISBN, GenreID, AuthorID, PublisherID, YearPublished, Pages, Price) 
              VALUES (@BookID, @Title, @ISBN, @GenreID, @AuthorID, @PublisherID, @YearPublished, @Pages, @Price)`);
      res.json({ success: true, message: "Book added successfully!" });
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  },
);

app.delete(
  "/api/books-protected/:id",
  auth.vulnerableJWTMiddleware,
  async (req, res) => {
    try {
      // VULNERABILITY: Trusts JWT role claim without verification!
      if (req.user.role !== "Admin") {
        return res.status(403).json({ error: "Admin access required" });
      }

      const result = await pool
        .request()
        .input("BookID", sql.NVarChar, req.params.id)
        .query("DELETE FROM Books WHERE BookID=@BookID");

      res.json({
        success: result.rowsAffected[0] > 0,
        message:
          result.rowsAffected[0] > 0
            ? "Book deleted successfully!"
            : "Book not found",
      });
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  },
);

// Similar for members
app.get(
  "/api/members-protected",
  auth.vulnerableJWTMiddleware,
  async (req, res) => {
    try {
      const result = await pool.request().query("SELECT * FROM Members");
      res.json(result.recordset);
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  },
);

app.delete(
  "/api/members-protected/:id",
  auth.vulnerableJWTMiddleware,
  async (req, res) => {
    try {
      if (req.user.role !== "Admin") {
        return res.status(403).json({ error: "Admin access required" });
      }
      const result = await pool
        .request()
        .input("MemberID", sql.NVarChar, req.params.id)
        .query("DELETE FROM Members WHERE MemberID=@MemberID");
      res.json({ success: result.rowsAffected[0] > 0 });
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  },
);

// ========================================================================================
// ========================================================================================
// ========================================================================================



// ==================== AUTHORS ROUTES ====================
app.get("/api/authors", async (req, res) => {
  try {
    const result = await pool.request().query("SELECT * FROM Authors");
    res.json(result.recordset);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post("/api/authors", async (req, res) => {
  try {
    const { AuthorID, AuthorName, Country, BirthYear } = req.body;
    await pool
      .request()
      .input("AuthorID", sql.NVarChar, AuthorID)
      .input("AuthorName", sql.NVarChar, AuthorName)
      .input("Country", sql.NVarChar, Country)
      .input("BirthYear", sql.Int, BirthYear)
      .query(
        "INSERT INTO Authors (AuthorID, AuthorName, Country, BirthYear) VALUES (@AuthorID, @AuthorName, @Country, @BirthYear)",
      );
    res.json({ success: true, message: "Author added successfully!" });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.put("/api/authors/:id", async (req, res) => {
  try {
    const { AuthorName, Country, BirthYear } = req.body;
    const result = await pool
      .request()
      .input("AuthorID", sql.NVarChar, req.params.id)
      .input("AuthorName", sql.NVarChar, AuthorName)
      .input("Country", sql.NVarChar, Country)
      .input("BirthYear", sql.Int, BirthYear)
      .query(
        "UPDATE Authors SET AuthorName=@AuthorName, Country=@Country, BirthYear=@BirthYear WHERE AuthorID=@AuthorID",
      );
    res.json({
      success: result.rowsAffected[0] > 0,
      message:
        result.rowsAffected[0] > 0
          ? "Author updated successfully!"
          : "Author not found",
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.delete("/api/authors/:id", async (req, res) => {
  try {
    const result = await pool
      .request()
      .input("AuthorID", sql.NVarChar, req.params.id)
      .query("DELETE FROM Authors WHERE AuthorID=@AuthorID");
    res.json({
      success: result.rowsAffected[0] > 0,
      message:
        result.rowsAffected[0] > 0
          ? "Author deleted successfully!"
          : "Author not found",
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get("/api/authors/search/:name", async (req, res) => {
  try {
    const result = await pool
      .request()
      .input("Name", sql.NVarChar, "%" + req.params.name + "%")
      .query("SELECT * FROM Authors WHERE AuthorName LIKE @Name");
    res.json(result.recordset);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ==================== PUBLISHERS ROUTES ====================
app.get("/api/publishers", async (req, res) => {
  try {
    const result = await pool.request().query("SELECT * FROM Publishers");
    res.json(result.recordset);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post("/api/publishers", async (req, res) => {
  try {
    const { PublisherID, PublisherName, Country, Contact } = req.body;
    await pool
      .request()
      .input("PublisherID", sql.NVarChar, PublisherID)
      .input("PublisherName", sql.VarChar, PublisherName)
      .input("Country", sql.VarChar, Country)
      .input("Contact", sql.NVarChar, Contact)
      .query(
        "INSERT INTO Publishers (PublisherID, PublisherName, Country, Contact) VALUES (@PublisherID, @PublisherName, @Country, @Contact)",
      );
    res.json({ success: true, message: "Publisher added successfully!" });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.put("/api/publishers/:id", async (req, res) => {
  try {
    const { PublisherName, Country, Contact } = req.body;
    const result = await pool
      .request()
      .input("PublisherID", sql.NVarChar, req.params.id)
      .input("PublisherName", sql.VarChar, PublisherName)
      .input("Country", sql.VarChar, Country)
      .input("Contact", sql.NVarChar, Contact)
      .query(
        "UPDATE Publishers SET PublisherName=@PublisherName, Country=@Country, Contact=@Contact WHERE PublisherID=@PublisherID",
      );
    res.json({
      success: result.rowsAffected[0] > 0,
      message:
        result.rowsAffected[0] > 0
          ? "Publisher updated successfully!"
          : "Publisher not found",
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.delete("/api/publishers/:id", async (req, res) => {
  try {
    const result = await pool
      .request()
      .input("PublisherID", sql.NVarChar, req.params.id)
      .query("DELETE FROM Publishers WHERE PublisherID=@PublisherID");
    res.json({
      success: result.rowsAffected[0] > 0,
      message:
        result.rowsAffected[0] > 0
          ? "Publisher deleted successfully!"
          : "Publisher not found",
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get("/api/publishers/search/:name", async (req, res) => {
  try {
    const result = await pool
      .request()
      .input("Name", sql.NVarChar, "%" + req.params.name + "%")
      .query("SELECT * FROM Publishers WHERE PublisherName LIKE @Name");
    res.json(result.recordset);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ==================== USERS ROUTES ====================
app.get("/api/users", async (req, res) => {
  try {
    const result = await pool.request().query("SELECT * FROM Users");
    res.json(result.recordset);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post("/api/users", async (req, res) => {
  try {
    const { UserID, Username, Password, Role } = req.body;
    await pool
      .request()
      .input("UserID", sql.NVarChar, UserID)
      .input("Username", sql.VarChar, Username)
      .input("Password", sql.NVarChar, Password)
      .input("Role", sql.VarChar, Role)
      .query(
        "INSERT INTO Users (UserID, Username, Password, Role) VALUES (@UserID, @Username, @Password, @Role)",
      );
    res.json({ success: true, message: "User added successfully!" });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.put("/api/users/:id", async (req, res) => {
  try {
    const { Username, Password, Role } = req.body;
    const result = await pool
      .request()
      .input("UserID", sql.NVarChar, req.params.id)
      .input("Username", sql.VarChar, Username)
      .input("Password", sql.NVarChar, Password)
      .input("Role", sql.VarChar, Role)
      .query(
        "UPDATE Users SET Username=@Username, Password=@Password, Role=@Role WHERE UserID=@UserID",
      );
    res.json({
      success: result.rowsAffected[0] > 0,
      message:
        result.rowsAffected[0] > 0
          ? "User updated successfully!"
          : "User not found",
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.delete("/api/users/:id", async (req, res) => {
  try {
    const result = await pool
      .request()
      .input("UserID", sql.NVarChar, req.params.id)
      .query("DELETE FROM Users WHERE UserID=@UserID");
    res.json({
      success: result.rowsAffected[0] > 0,
      message:
        result.rowsAffected[0] > 0
          ? "User deleted successfully!"
          : "User not found",
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get("/api/users/search/:username", async (req, res) => {
  try {
    const result = await pool
      .request()
      .input("Username", sql.NVarChar, "%" + req.params.username + "%")
      .query("SELECT * FROM Users WHERE Username LIKE @Username");
    res.json(result.recordset);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ==================== BORROWING ROUTES ====================
app.get("/api/borrowing", async (req, res) => {
  try {
    const result = await pool.request().query(`
            SELECT b.BorrowID, b.MemberID, b.CopyID, b.Title,
                   c.ShelfLocation, b.BorrowDate, b.DueDate, b.ReturnDate
            FROM Borrowing b
            JOIN Copies c ON b.CopyID = c.CopyID`);
    res.json(result.recordset);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post("/api/borrowing", async (req, res) => {
  try {
    const { BorrowID, Title, MemberID, CopyID, BorrowDate, DueDate } = req.body;
    await pool
      .request()
      .input("BorrowID", sql.NVarChar, BorrowID)
      .input("Title", sql.NVarChar, Title)
      .input("MemberID", sql.NVarChar, MemberID)
      .input("CopyID", sql.NVarChar, CopyID)
      .input("BorrowDate", sql.Date, BorrowDate)
      .input("DueDate", sql.Date, DueDate)
      .query(`INSERT INTO Borrowing (BorrowID, Title, MemberID, CopyID, BorrowDate, DueDate) 
                    VALUES (@BorrowID, @Title, @MemberID, @CopyID, @BorrowDate, @DueDate)`);
    res.json({ success: true, message: "Book borrowed successfully!" });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.put("/api/borrowing/return/:id", async (req, res) => {
  try {
    const { ReturnDate } = req.body;
    const result = await pool
      .request()
      .input("BorrowID", sql.NVarChar, req.params.id)
      .input("ReturnDate", sql.Date, ReturnDate)
      .query(
        "UPDATE Borrowing SET ReturnDate=@ReturnDate WHERE BorrowID=@BorrowID",
      );
    res.json({
      success: result.rowsAffected[0] > 0,
      message:
        result.rowsAffected[0] > 0
          ? "Book returned successfully!"
          : "Borrow record not found",
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get("/api/borrowing/search/:title", async (req, res) => {
  try {
    const result = await pool
      .request()
      .input("Title", sql.NVarChar, "%" + req.params.title + "%")
      .query(`SELECT b.BorrowID, b.MemberID, b.CopyID, b.Title,
                           c.ShelfLocation, b.BorrowDate, b.DueDate, b.ReturnDate
                    FROM Borrowing b
                    JOIN Copies c ON b.CopyID = c.CopyID
                    WHERE b.Title LIKE @Title`);
    res.json(result.recordset);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ==================== AVAILABILITY ROUTES ====================
app.get("/api/availability/search/:bookName", async (req, res) => {
  try {
    const result = await pool
      .request()
      .input("BookName", sql.NVarChar, req.params.bookName + "%")
      .query(`SELECT b.Title, b.ISBN
                    FROM Books b
                    INNER JOIN Copies c ON b.BookID = c.BookID
                    WHERE c.IsAvailable = 1 AND b.Title LIKE @BookName`);
    res.json(result.recordset);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ==================== FINES ROUTES ====================
app.get("/api/fines", async (req, res) => {
  try {
    const result = await pool.request().query("SELECT * FROM Fines");
    res.json(result.recordset);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post("/api/fines", async (req, res) => {
  try {
    const { FineID, BorrowID, FineAmount, Paid, PaidDate } = req.body;
    await pool
      .request()
      .input("FineID", sql.NVarChar, FineID)
      .input("BorrowID", sql.NVarChar, BorrowID)
      .input("FineAmount", sql.Float, FineAmount)
      .input("Paid", sql.Bit, Paid)
      .input("PaidDate", sql.Date, PaidDate)
      .query(
        "INSERT INTO Fines (FineID, BorrowID, FineAmount, Paid, PaidDate) VALUES (@FineID, @BorrowID, @FineAmount, @Paid, @PaidDate)",
      );
    res.json({ success: true, message: "Fine added successfully!" });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.put("/api/fines/:id", async (req, res) => {
  try {
    const { BorrowID, FineAmount, Paid, PaidDate } = req.body;
    const result = await pool
      .request()
      .input("FineID", sql.NVarChar, req.params.id)
      .input("BorrowID", sql.NVarChar, BorrowID)
      .input("FineAmount", sql.Float, FineAmount)
      .input("Paid", sql.Bit, Paid)
      .input("PaidDate", sql.Date, PaidDate)
      .query(
        "UPDATE Fines SET BorrowID=@BorrowID, FineAmount=@FineAmount, Paid=@Paid, PaidDate=@PaidDate WHERE FineID=@FineID",
      );
    res.json({
      success: result.rowsAffected[0] > 0,
      message:
        result.rowsAffected[0] > 0
          ? "Fine updated successfully!"
          : "Fine not found",
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.delete("/api/fines/:id", async (req, res) => {
  try {
    const result = await pool
      .request()
      .input("FineID", sql.NVarChar, req.params.id)
      .query("DELETE FROM Fines WHERE FineID=@FineID");
    res.json({
      success: result.rowsAffected[0] > 0,
      message:
        result.rowsAffected[0] > 0
          ? "Fine deleted successfully!"
          : "Fine not found",
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get("/api/fines/search/:borrowId", async (req, res) => {
  try {
    const result = await pool
      .request()
      .input("BorrowID", sql.NVarChar, "%" + req.params.borrowId + "%")
      .query("SELECT * FROM Fines WHERE BorrowID LIKE @BorrowID");
    res.json(result.recordset);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ==================== REPORTS ROUTES ====================
app.get("/api/reports/most-borrowed", async (req, res) => {
  try {
    const result = await pool.request().query(`
            SELECT TOP 10 B.Title, COUNT(*) AS BorrowCount 
            FROM Borrowing BR 
            JOIN Copies C ON BR.CopyID = C.CopyID 
            JOIN Books B ON C.BookID = B.BookID 
            GROUP BY B.Title 
            ORDER BY BorrowCount DESC`);
    res.json(result.recordset);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get("/api/reports/overdue", async (req, res) => {
  try {
    const result = await pool.request().query(`
            SELECT m.FullName AS MemberName, b.Title AS BookTitle, br.DueDate, 
                   DATEDIFF(day, br.DueDate, GETDATE()) AS DaysOverdue, br.FineAmount 
            FROM Borrowing br 
            JOIN Members m ON br.MemberID = m.MemberID 
            JOIN Copies c ON br.CopyID = c.CopyID 
            JOIN Books b ON c.BookID = b.BookID 
            WHERE br.ReturnDate IS NULL AND br.DueDate < GETDATE()`);
    res.json(result.recordset);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get("/api/reports/current-borrowed", async (req, res) => {
  try {
    const result = await pool.request().query(`
            SELECT M.FullName AS MemberName, B.Title, BR.BorrowDate, BR.DueDate 
            FROM Borrowing BR 
            JOIN Members M ON BR.MemberID = M.MemberID 
            JOIN Copies C ON BR.CopyID = C.CopyID 
            JOIN Books B ON C.BookID = B.BookID 
            WHERE BR.ReturnDate IS NULL`);
    res.json(result.recordset);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get("/api/reports/inventory", async (req, res) => {
  try {
    const result = await pool.request().query(`
            SELECT B.Title, G.GenreName, A.AuthorName, P.PublisherName, 
                   COUNT(C.CopyID) AS TotalCopies, 
                   SUM(CASE WHEN C.IsAvailable = 1 THEN 1 ELSE 0 END) AS AvailableCopies, 
                   SUM(CASE WHEN C.IsAvailable = 0 THEN 1 ELSE 0 END) AS BorrowedCopies 
            FROM Books B 
            JOIN Genres G ON B.GenreID = G.GenreID 
            JOIN Authors A ON B.AuthorID = A.AuthorID 
            JOIN Publishers P ON B.PublisherID = P.PublisherID 
            JOIN Copies C ON B.BookID = C.BookID 
            GROUP BY B.Title, G.GenreName, A.AuthorName, P.PublisherName`);
    res.json(result.recordset);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ==================== GENRES ROUTES ====================
app.get("/api/genres", async (req, res) => {
  try {
    const result = await pool.request().query("SELECT * FROM Genres");
    res.json(result.recordset);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ==================== COPIES ROUTES ====================
app.get("/api/copies", async (req, res) => {
  try {
    const result = await pool.request().query("SELECT * FROM Copies");
    res.json(result.recordset);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ==================== BACKUP & RESTORE ROUTES ====================
app.post("/api/backup", async (req, res) => {
  try {
    const { backupPath } = req.body;

    if (!backupPath) {
      return res
        .status(400)
        .json({ success: false, error: "Backup path is required" });
    }

    const dbName = process.env.DB_NAME || "Library Database Management System";

    // Create backup using SQL Server BACKUP command
    await pool.request().query(`
            BACKUP DATABASE [${dbName}] 
            TO DISK = '${backupPath}' 
            WITH FORMAT, INIT, 
            NAME = 'Library Database Backup',
            SKIP, NOREWIND, NOUNLOAD, STATS = 10
        `);

    res.json({ success: true, message: "Backup created successfully" });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

app.post("/api/restore", async (req, res) => {
  try {
    const { restorePath } = req.body;

    if (!restorePath) {
      return res
        .status(400)
        .json({ success: false, error: "Restore path is required" });
    }

    const dbName = process.env.DB_NAME || "Library Database Management System";

    // Set database to single user mode, restore, then set back to multi user
    await pool.request().query(`
            ALTER DATABASE [${dbName}] SET SINGLE_USER WITH ROLLBACK IMMEDIATE;
        `);

    await pool.request().query(`
            RESTORE DATABASE [${dbName}] 
            FROM DISK = '${restorePath}' 
            WITH REPLACE, STATS = 10
        `);

    await pool.request().query(`
            ALTER DATABASE [${dbName}] SET MULTI_USER;
        `);

    res.json({ success: true, message: "Database restored successfully" });
  } catch (err) {
    // Try to set back to multi user mode if restore failed
    try {
      const dbName =
        process.env.DB_NAME || "Library Database Management System";
      await pool.request().query(`ALTER DATABASE [${dbName}] SET MULTI_USER;`);
    } catch (e) {
      // Ignore error
    }
    res.status(500).json({ success: false, error: err.message });
  }
});

// Serve static files
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
