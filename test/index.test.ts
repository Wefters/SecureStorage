// @vitest-environment jsdom
import { afterEach, describe, expect, it } from "vitest";
import { installMockBridge, uninstallMockBridge } from "@wefterjs/core/testing";
import { WefterBridgeError } from "@wefterjs/core";
import { SecureStorage } from "../src/index.js";

afterEach(() => {
  uninstallMockBridge();
});

describe("SecureStorage.set", () => {
  it("forwards key/value and resolves with success", async () => {
    installMockBridge({
      "secure-storage": (method, payload) => {
        expect(method).toBe("set");
        expect(payload).toEqual({ key: "authToken", value: "abc123" });
        return { success: true };
      },
    });

    const result = await SecureStorage.set({ key: "authToken", value: "abc123" });

    expect(result).toEqual({ success: true });
  });
});

describe("SecureStorage.get", () => {
  it("resolves with the stored value", async () => {
    installMockBridge({
      "secure-storage": (method, payload) => {
        expect(method).toBe("get");
        expect(payload).toEqual({ key: "authToken" });
        return { value: "abc123" };
      },
    });

    const result = await SecureStorage.get({ key: "authToken" });

    expect(result).toEqual({ value: "abc123" });
  });

  it("resolves with null when nothing is stored under that key", async () => {
    installMockBridge({
      "secure-storage": () => ({ value: null }),
    });

    const result = await SecureStorage.get({ key: "missing" });

    expect(result.value).toBeNull();
  });
});

describe("SecureStorage.remove", () => {
  it("forwards key and resolves with success", async () => {
    installMockBridge({
      "secure-storage": (method, payload) => {
        expect(method).toBe("remove");
        expect(payload).toEqual({ key: "authToken" });
        return { success: true };
      },
    });

    const result = await SecureStorage.remove({ key: "authToken" });

    expect(result).toEqual({ success: true });
  });
});

describe("error propagation", () => {
  it("surfaces a native rejection as a WefterBridgeError", async () => {
    installMockBridge({
      "secure-storage": () => {
        throw new Error("Key must not exceed 255 characters.");
      },
    });

    const call = SecureStorage.set({ key: "x".repeat(300), value: "v" });

    await expect(call).rejects.toBeInstanceOf(WefterBridgeError);
    await expect(call).rejects.toMatchObject({
      code: "MOCK_ERROR",
      message: "Key must not exceed 255 characters.",
    });
  });
});
