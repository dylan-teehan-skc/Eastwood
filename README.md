# Eastwood

Eastwood is a secure file-sharing application built with Qt6, designed to provide robust encryption and secure communication between users. The application supports user registration, device authentication via QR codes, secure file uploads, and encrypted file sharing.

## Features

- **User Authentication**: Secure login and registration with passphrase validation.
- **Device Registration**: QR code-based device authentication for multi-device support.
- **Secure File Sharing**: Encrypted file uploads and secure file sharing between users.
- **Cryptographic Security**: Utilizes libsodium for cryptographic operations and secure key management.
- **Database Security**: Uses SQLCipher for encrypted database storage.
- **Cross-Platform**: Built with Qt6, supporting multiple platforms including macOS (minimum version 10.15).

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

**Cryptographic Design**

![Sending A Message](https://github.com/user-attachments/assets/cdc78429-ae19-4e64-a03b-e99fc30ae9b0)
![Responding to a message](https://github.com/user-attachments/assets/67f94434-57aa-4dbe-a642-0aa4700308cf)
![Ratchet Key Derivation](https://github.com/user-attachments/assets/e51c3bd5-2f07-4a7e-99dc-f61f04fe3f7a)
![New Device](https://github.com/user-attachments/assets/3293850e-a39a-4926-b763-b803f0d6761c)
![Login Flow](https://github.com/user-attachments/assets/9d93869e-210b-454f-8f48-a2df00f32bcb)
![DB Structure](https://github.com/user-attachments/assets/482e0aaa-ef79-4386-9dc8-cf40deef7edc)
![DB Structure-1](https://github.com/user-attachments/assets/b240c9c3-b5b8-44ae-840a-a3b4af5c9234)
![File Encryption](https://github.com/user-attachments/assets/c859ee5c-24a5-4ec5-96bd-787d4cd6191d)
![Auth Post](https://github.com/user-attachments/assets/c097ceae-31bc-4fb9-9e77-405575d33103)
![Auth Get](https://github.com/user-attachments/assets/e5e7bda4-ad79-4658-9486-382b03d7485e)

## Dependencies

- **Qt6**: Core, Gui, Widgets, UiTools, Concurrent.
- **OpenSSL**: For SSL/TLS support.
- **OpenCV**: For image processing (e.g., QR code scanning).
- **libsodium**: For cryptographic operations.
- **SQLCipher**: For encrypted database storage.
- **nlohmann_json**: For JSON parsing.
- **GoogleTest**: For testing.
