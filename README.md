# @wefterjs/secure-storage

Official Wefter plugin for hardware-backed encrypted storage on Android (`EncryptedSharedPreferences`) and iOS (`Keychain`).

---

## Features

- 🔐 **Hardware Encryption**: Hardware-backed AES-256 GCM encryption on Android (`MasterKey`) and iOS Keychain (`kSecClassGenericPassword`).
- 🔑 **Key-Value API**: Fast async key-value `set`, `get`, and `remove` methods.
- 🛡️ **Zero Persistence Leaks**: Stored items survive application reboots and updates, isolated from plain unencrypted web local storage.

---

## Installation & Setup

1. Add the plugin to your Wefter project:

```bash
wefter add @wefterjs/secure-storage
```

2. Synchronize native projects:

```bash
wefter sync
```

---

## JavaScript API Reference

Import `invokeNative` from `@wefterjs/core`:

```ts
import { invokeNative } from "@wefterjs/core";
```

### 1. `set(options)`

Securely stores an encrypted key-value pair.

```ts
interface SetStorageOptions {
  key: string; // Storage key identifier
  value: string; // Secret string value to encrypt and persist
}

await invokeNative("secure-storage", "set", {
  key: "authToken",
  value: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
});
```

### 2. `get(options)`

Retrieves and decrypts a value from secure storage.

```ts
interface GetStorageOptions {
  key: string;
}

interface GetStorageResult {
  value: string | null;
}

const res = await invokeNative<GetStorageResult>("secure-storage", "get", {
  key: "authToken",
});

if (res.value) {
  console.log("Retrieved token:", res.value);
} else {
  console.log("No token found under key");
}
```

### 3. `remove(options)`

Permanently removes a key-value item from secure storage.

```ts
interface RemoveStorageOptions {
  key: string;
}

await invokeNative("secure-storage", "remove", {
  key: "authToken",
});
```

---

## Complete Usage Example

```ts
import { invokeNative } from "@wefterjs/core";

export class AuthSession {
  static async saveToken(token: string): Promise<void> {
    await invokeNative("secure-storage", "set", { key: "session_jwt", value: token });
  }

  static async getToken(): Promise<string | null> {
    const res = await invokeNative<{ value: string | null }>("secure-storage", "get", {
      key: "session_jwt",
    });
    return res.value;
  }

  static async clearSession(): Promise<void> {
    await invokeNative("secure-storage", "remove", { key: "session_jwt" });
  }
}
```
