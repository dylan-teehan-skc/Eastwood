# Eastwood

Eastwood is a secure file-sharing application built with Qt6, designed to provide robust encryption and secure communication between users. The application supports user registration, device authentication via QR codes, secure file uploads, and encrypted file sharing.

## Features

- **User Authentication**: Secure login and registration with passphrase validation.
- **Device Registration**: QR code-based device authentication for multi-device support.
- **Secure File Sharing**: Encrypted file uploads and secure file sharing between users.
- **Cryptographic Security**: Utilizes libsodium for cryptographic operations and secure key management.
- **Database Security**: Uses SQLCipher for encrypted database storage.
- **Cross-Platform**: Built with Qt6, supporting multiple platforms including macOS (minimum version 10.15).

## Project Structure

- **src/**: Contains the main source code.
  - **algorithms/**: Cryptographic algorithms and constants.
  - **auth/**: User authentication and device registration logic.
  - **communication/**: File upload, send, and revoke functionalities.
  - **database/**: Database schema and operations.
  - **endpoints/**: API endpoints for server communication.
  - **key_exchange/**: Key exchange mechanisms and ratchet protocols.
  - **libraries/**: HTTP client and base client implementations.
  - **sessions/**: Session management and key bundle handling.
  - **ui/**: User interface components and windows.
  - **utils/**: Utility functions and helpers.
- **test/**: Contains test files for unit and integration testing.
- **scripts/**: Utility scripts for building and running the application.
- **external/**: Third-party libraries, including QR code generation.

## Dependencies

- **Qt6**: Core, Gui, Widgets, UiTools, Concurrent.
- **OpenSSL**: For SSL/TLS support.
- **OpenCV**: For image processing (e.g., QR code scanning).
- **libsodium**: For cryptographic operations.
- **SQLCipher**: For encrypted database storage.
- **nlohmann_json**: For JSON parsing.
- **GoogleTest**: For testing.

## Building the Project

1. **Prerequisites**: Ensure you have CMake (version 3.16 or higher) and the required dependencies installed.
2. **Clone the Repository**: 
   ```bash
   git clone https:://https://github.com/Fred-Sheppard/Eastwood.git
   cd Eastwood
   ```
3. **Build the Project**:
   ```bash
   mkdir build
   cd build
   cmake ..
   make
   ```
4. **Run the Application**:
   ```bash
   ./Eastwood
   ```

## Testing

The project includes unit and integration tests. To run the tests, use the following commands:

```bash
cd build
make EastwoodTests
./EastwoodTests
make IntegrationTests
./IntegrationTests
```
