import { definePlugin } from "@wefterjs/core";

export interface SecureStorageSetOptions {
  key: string;
  value: string;
}

export interface SecureStorageGetOptions {
  key: string;
}

export interface SecureStorageGetResult {
  value: string | null;
}

export interface SecureStorageRemoveOptions {
  key: string;
}

export interface SecureStorageWriteResult {
  success: true;
}

export const SecureStorage = definePlugin<{
  set: (options: SecureStorageSetOptions) => Promise<SecureStorageWriteResult>;
  get: (options: SecureStorageGetOptions) => Promise<SecureStorageGetResult>;
  remove: (options: SecureStorageRemoveOptions) => Promise<SecureStorageWriteResult>;
}>("secure-storage", { set: true, get: true, remove: true });
