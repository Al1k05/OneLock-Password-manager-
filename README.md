# OneLock Password Manager

OneLock is a secure desktop password manager built with Python that helps users store and manage their application credentials safely. The application features strong-grade encryption, an intuitive graphical interface, and comprehensive password management capabilities.

![alt text](<assets/window pop-up.gif>)


The password manager includes several powerful features designed to enhance security and user experience:

Security Features:
. Fernet symmetric encryption for all stored passwords
. Bcrypt password hashing for master account credentials
. Automated encryption key generation and management
. Secure credential storage in SQLite database
. Multi-user system to for individual restricted access

User Interface:
. Modern dark-themed interface using CustomTkinter
. Intuitive tabbed layout for dashboard and password management
. Real-time search functionality across all stored credentials
. Visual login activity tracking with matplotlib charts
. Responsive design that adapts to different screen sizes

Password Management:
. Create, read, update, and delete password records
. Store application names, usernames, passwords, and associated emails
. Export all credentials to CSV format for backup purposes
. View decrypted passwords on demand with confirmation
. Track creation dates for all password entries

Analytics Dashboard:
. Bar chart visualization of login frequency by month
. Historical login tracking for security monitoring
. Interactive matplotlib charts embedded in the interface
. Automatic dashboard updates after each login

 System Requirements:
Before installing OneLock, make sure your system meets the following requirements:
. Python 3.8 or higher
. Operating System: Windows 10/11, macOS 10.14+, or Linux (Ubuntu 20.04+)
. Minimum 4GB RAM
. 500MB free disk space

Installation Guide
 Step 1:Download the Repository
Download the OneLock source code to your local machine. If you have Git installed, use:

```bash
git clone <repository-url>
cd onelock-password-manager
```
Step 2: Set Up Python Environment
It's recommended to create a virtual environment to avoid conflicts with other Python packages:

```bash
python -m venv venv
```
Activating the virtual environment:

On Windows:
```bash
venv\Scripts\Activate.ps1
```
On macOS/Linux:
```bash
source venv/bin/activate
```

Step 3: Install Requirements
Install all necessary Python packages using the requirements file:

```bash
pip install -r requirement.txt
```
This will install the following dependencies:
. customtkinter: Modern UI framework for tkinter
. cryptography: Encryption library for password security
. numpy: Numerical computing for data processing
. pandas: Data manipulation and analysis
. bcrypt: Password hashing algorithm
. matplotlib: Visualization library for charts
. Pillow: Image processing library

Step 4: Create Required Directories

The application needs specific directories for assets and data storage:

```bash
 assets
```
Step 5: Add Application Assets (Optional)

. "assets/logo.png": Application logo (100x100 pixels recommended)
. "assets/icons.ic": Window icon file
The application will still run though without these files, but they enhance the visual appearance.

Step 6: Launch the Application
Run the main script to start OneLock:

```bash
python main.py
```
The application window should appear, showing the login/registration screen.

First-Time Setup
When you run OneLock for the first time, follow these steps:
1. Create Your Master Account: Click the "Register" button on the login screen
2. Enter Registration Details: Provide a unique username, email address, and strong master password
3. Confirm Password: Re-enter your password to ensure accuracy
4. Submit Registration: Click "Submit Registration" to create your account

Important notes about registration:
. Multiple master account can be created, but cannott be accessed by another
. Choose a strong master password as it protects all your stored credentials
. Your master password is hashed using bcrypt and cannot be recovered if forgotten

Application Structure
Understanding the project structure helps with maintenance and customization:

```
onelock-password-manager/
│
├── main.py                  # Application entry point
├── password_manager.py      # Core application logic and UI
├── database.py              # Database initialization and utilities
├── requirement.txt          # Python package dependencies
│
├── assets/                  # Visual resources (optional)
│   ├── logo.png            # Application logo
│   └── icons.ico           # Window icon
│
├── data/                    # Database storage
│   └── manageapp.db        # SQLite database file (auto-created)
│
└── secret.key              # Encryption key (auto-generated)
│
└──LICENSE
```

 Database Architecture
OneLock uses SQLite for data persistence with the following table structure:

 Account Table
Stores master user account information:

| Column | Type | Description |
|----------|------|-------------|
| username | TEXT | Unique username for login |
| password | TEXT | Bcrypt-hashed master password |
| email    | TEXT | User's email address |
| admin    | TEXT | Admin status flag |
| creationdate | NUMERIC | Account creation timestamp |

Userapplication Table
Stores encrypted password records for applications:

| Column | Type | Description |
|---------|------|-------------|
| nameapp | TEXT | Application or service name |
| user_app | TEXT | Username for the application |
| password | TEXT | Encrypted password (Fernet) |
| email_in_app | TEXT | Email associated with the application |
| creationdate | NUMERIC | Record creation timestamp |
| username | TEXT | Foreign key to account table |

Event Table
Tracks login activity for analytics:

| Column | Type | Description |
|--------|------|-------------|
| logindate | NUMERIC | Timestamp of login event |
| event | TEXT | Event type (e.g., "login") |
| username | TEXT | User who triggered the event |

Infoapplication Table
Stores application metadata:

| Column | Type | Description |
|--------|------|-------------|
| nameapp | TEXT | Primary key, application name |

 ifuserapp Table
Links users to applications:

| Column | Type | Description |
|--------|------|-------------|
| nameapp | TEXT | Foreign key to infoapplication |

userinfo Table
Stores additional user profile information:

| Column | Type | Description |
|--------|------|-------------|
| personid | INTEGER | Primary key |
| firstname | TEXT | User's first name |
| lastname | TEXT | User's last name |
| email | TEXT | Contact email |
| phone | TEXT | Contact phone number |

 Core Functionality

Encryption System
The application employs robust encryption to protect stored passwords:

Key Generation Process:
When OneLock starts for the first time, it generates a unique Fernet encryption key and saves it to `secret.key`. This key remains consistent across sessions, ensuring previously encrypted passwords can be decrypted. The `_load_or_generate_key()` method handles this:

```python
def _load_or_generate_key(self):
    key_path = "secret.key"
    if os.path.exists(key_path):
        with open(key_path, "rb") as f:
            return f.read()
    else:
        key = Fernet.generate_key()
        with open(key_path, "wb") as f:
            f.write(key)
        return key
```

Encryption Process:
When saving a particluar password, the application encrypts it using Fernet symmetric encryption before storing it in the database:
```python
encrypted_pass = self.cipher.encrypt(app_pass.encode('utf-8'))
```

Decryption Process:
Passwords are only decrypted when explicitly requested by the user through the "Show Password" button:

```python
decrypted_pass = self.cipher.decrypt(encrypted_pass).decode('utf-8')
```

User Authentication
The login system uses bcrypt for secure password hashing:

Registration: When creating an account, the master password is hashed with a randomly generated salt:

```python
hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
```

Login Verification: During login, the entered password is compared against the stored hash:

```python
stored_hash = record['password'].iloc[0].encode('utf-8')
if bcrypt.checkpw(password.encode('utf-8'), stored_hash):
    Authentication successful
```

The "login()" method validates credentials and records login events for analytics tracking.

 Password Management Operations

Adding New Records**:
The "add_recordtree()" method handles creating new password entries:
. Validates that required fields (application name, username, password) are filled
. Encrypts the password using the Fernet cipher
. Inserts the record into the userapplication table
. Links the record to the current user via foreign key
. Refreshes the display to show the new entry

Updating Existing Records:
The "update_recordtree()" method allows modifying stored credentials:
. Retrieves the selected record from the tree view
. Validates new input data
. If a new password is provided, encrypts it
. Updates the database record while preserving the original password if no new one is provided
. Refreshes the display to reflect changes

Deleting Records:
The "delete_treerecord()" method removes unwanted entries:
. Confirms the deletion with a dialog box
. Removes the record from the database
. Updates the tree view to remove the deleted entry

Viewing Passwords:
The "show_application_password()" method reveals encrypted passwords:
. Retrieves the encrypted password from the DataFrame
. Decrypts it using the Fernet cipher
. Displays the plaintext password in a secure dialog box

Search Functionality
The search feature allows real-time filtering of stored credentials:

```python
def search_records(self):
    search_term = self.search_entry.get().lower()
    if not search_term:
        self._populate_tree()
        return
    
    mask = (df_copy["nameapp"].str.lower().str.contains(search_term)) | \
           (df_copy["user_app"].str.lower().str.contains(search_term)) | \
           (df_copy["email_in_app"].str.lower().str.contains(search_term))
    
    self._populate_tree(df_copy[mask])
```
The search operates on application names, usernames, and email addresses. Passwords are excluded from search results for security purposes.

Data Export
Users can export their password vault to CSV format for backup or migration:

```python
def export_all_records(self):
    df_to_export = self.df_passwords.copy()
    df_to_export['password'] = df_to_export['password'].apply(
        lambda p: self.cipher.decrypt(p).decode('utf-8') if p else ""
    )
    df_to_export.to_csv(file_path, index=False)
```
The export process decrypts all passwords before writing to the CSV file, creating a plaintext backup that should be stored securely.

Analytics Dashboard
The dashboard visualizes login patterns using matplotlib:

Data Collection:
Login events are recorded in the event table each time a user successfully authenticates:

```python
c.execute("INSERT INTO event (logindate, event, username) VALUES (datetime('now'), 'login', ?)", 
          (self.username,))
```

Visualization:
The "update_dashboard()" method queries login data and generates a bar chart:
. Retrieves all login events for the current user
. Groups events by month-year
. Counts logins per month
. Creates a matplotlib bar chart with custom styling
. Embeds the chart in the CustomTkinter interface
The chart uses a dark theme to match the application interface and updates automatically after each login.

User Interface Components

Login Screen
The login screen serves as the entry point to OneLock:

Components:
. Logo display
. Username input field
. Password input field (masked)
. Login button
. Register button 

Functionality:
The screen validates credentials against the database and handles transitions to the registration screen. After successful login, it records the event and switches to the main application interface.

Registration Screen
The registration screen appears when users click "Register":

Components:
. Username input field
. Email input field
. Password input field (is masked)
. Confirm password field (is masked)
. Submit button
. Back to login button

Validation:
The "submit_registration()" method performs several checks:
. Ensures all fields are filled
. Validates email format using regex
. Verifies passwords match
. Confirms username uniqueness
. Enforces minimum password length requirements

 Main Application Interface
After login, users access the primary interface with two tabs:

Dashboard Tab:
This displays login activity analytics with a matplotlib bar chart showing monthly login frequency. The chart automatically updates and uses a color scheme matching the dark theme.

Application Manager Tab:
It features a split layout:
. Left side: Tree view displaying all stored passwords
. Right side: Control panel with buttons and input fields

Tree View Columns:
. Application Name
. Username
. Password (displayed as asterisks)
. Email
. Creation Date

 Control Panel
The right-side panel contains:
Input Fields:
. Application Name entry
. Username entry
. Password entry
. Email entry

Action Buttons:
. Add Record: Creates new password entry
. Update Record: Modifies selected entry
. Delete Record: Removes selected entry
. Clear Fields: Resets all input fields
. Show Password: Reveals decrypted password
. Export All Records: Saves vault to CSV

Each button triggers its corresponding method and includes error handling for invalid operations.

Security Considerations
OneLock implements several security measures:

Encryption:
All passwords stored in the database are encrypted using Fernet symmetric encryption. The encryption key is stored locally in "secret.key" and must be kept secure. Loss of this key results in permanent data loss.

Password Hashing:
The master password is hashed using bcrypt with automatic salt generation. This one-way hash cannot be reversed, protecting the master password even if the database is compromised.

Multi-User Design:
The application enables registration to one account that was registered with, reducing the attack surface and simplifying security management.

No Password Caching:
Decrypted passwords are never stored in memory longer than necessary and are only displayed when explicitly requested.

Database Permissions:
The SQLite database uses foreign key constraints with CASCADE rules to maintain data integrity and automatically clean up orphaned records.

 Important Security Notes

Users should be aware of these security considerations:

. Backup Your Encryption Key**: The "secret.key" file is essential for accessing encrypted passwords. Store a backup in a secure location.

. Master Password Recovery: There is no password recovery mechanism. If you forget your master password, your encrypted data cannot be accessed.

. Export File Security: CSV exports contain plaintext passwords and should be stored securely or deleted after use.

. Physical Security: Anyone with physical access to your computer while OneLock is running can view stored passwords.

. Database File: The "manageapp.db" file contains encrypted passwords but should still be treated as sensitive data.

 Troubleshooting

Common issues and solutions:

If application does not Start:
. Verify Python version (3.8+)
. Ensure all dependencies are installed
. Check for error messages in the terminal

Database Errors:
. Confirm the data directory exists and is writable
. Check file permissions on manageapp.db
. Delete the database file to reset (WARNING: loses all data)

If decryption fails:
. Ensure the secret.key file hasn't been modified
. Verify the key file is in the correct location
. Check that passwords were encrypted with the current key

Visual Issues:
. Update customtkinter to the latest version
. Verify display resolution meets minimum requirements
. Try different system themes if elements appear misaligned

Importing Errors:
. Reinstall dependencies using pip
. Check for conflicting package versions
. Use a fresh virtual environment

 Performance Optimization
For optimal performance with large password databases:

Database Indexing:
The application uses appropriate indexes on foreign key columns to speed up queries. Additional indexes can be added to frequently searched columns.

Data Loading:
Password records are loaded into a pandas DataFrame for efficient filtering and searching. This approach provides fast search operations even with hundreds of entries.

Chart Rendering:
The matplotlib chart uses fixed dimensions and minimal styling to ensure quick rendering. Login data is aggregated before visualization to reduce processing overhead.

 Customization Options

Users can customize various aspects of OneLock:
Appearance:
Modify the "set_appearance_mode()" and "set_default_color_theme()" calls in the "__init__" method to change the interface theme. Available modes: "dark", "light", "system". Available themes: "blue", "green", "dark-blue".

Window Dimensions:
Adjust the "geometry()" parameter in "run_app()" to change the default window size and position.

Database Location:
Modify the "db_path" parameter in "database.py" to store the database in a different location.

Chart Styling:
Customize colors, fonts, and layout in the "update_dashboard()" method to match personal preferences.

Code Organization:
The application follows object-oriented design with the main PasswordManager class encapsulating all functionality. Private methods (prefixed with "_") handle internal operations, while public methods provide the interface.

Error Handling:
Database operations are wrapped in try-except blocks with user-friendly error messages. The application uses SQLite's built-in transaction management for data consistency.

Data Flow:
. User interaction triggers event handlers
. Event handlers validate input and call database methods
. Database methods execute SQL queries with parameterized statements
. Results are processed and displayed through the UI
. Charts and displays are updated as needed


Version 1.0:
 Initial release with core password management features
 Fernet encryption implementation
 Basic dashboard analytics
 Single-user authentication system

Conclusion

OneLock provides a robust, secure solution for managing passwords across multiple applications. By combining strong encryption with an intuitive interface, it helps users maintain unique, complex passwords without the burden of memorization. The application balances security with usability, making password management accessible while maintaining high security standards.

The open architecture allows for customization and extension, enabling users to adapt the application to their specific needs. Whether for personal use or as a foundation for more complex password management solutions, OneLock offers a solid starting point with proven security practices and clean, maintainable code.

Regular use of OneLock, combined with good security hygiene and regular backups, significantly improves password security compared to reusing passwords or storing them in plaintext files. The visual analytics provide insights into usage patterns, while the export functionality ensures data portability and disaster recovery capabilities.
