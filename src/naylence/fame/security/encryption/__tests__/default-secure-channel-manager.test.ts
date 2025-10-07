import type { SecureAcceptFrame } from "naylence-core";
import { DefaultSecureChannelManager } from "../default-secure-channel-manager.js";
import { DefaultSecureChannelManagerFactory } from "../default-secure-channel-manager-factory.js";

describe("DefaultSecureChannelManager", () => {
  it("performs a full handshake and stores matching channel state on both peers", async () => {
    const client = new DefaultSecureChannelManager();
    const server = new DefaultSecureChannelManager();

    const channelId = "test-channel-1";
    const openFrame = client.generateOpenFrame(channelId);

    expect(openFrame.cid).toBe(channelId);
    expect(openFrame.alg).toBe("CHACHA20P1305");
    expect(Buffer.from(openFrame.ephPub, "base64").length).toBe(32);

    const acceptFrame = await server.handleOpenFrame(openFrame);
    expect(acceptFrame.ok).toBe(true);
    expect(server.hasChannel(channelId)).toBe(true);

    const completed = await client.handleAcceptFrame(acceptFrame);
    expect(completed).toBe(true);
    expect(client.hasChannel(channelId)).toBe(true);

    const clientChannels = client.channels;
    const serverChannels = server.channels;
    const clientState = clientChannels[channelId];
    const serverState = serverChannels[channelId];

    expect(clientState).toBeDefined();
    expect(serverState).toBeDefined();
    expect(clientState?.key.length).toBe(32);
    expect(serverState?.key.length).toBe(32);
    expect(Buffer.from(clientState!.key).toString("hex")).toBe(
      Buffer.from(serverState!.key).toString("hex")
    );
    expect(clientState?.noncePrefix.length).toBe(4);
    expect(serverState?.noncePrefix.length).toBe(4);
  });

  it("rejects unsupported algorithms when handling open frames", async () => {
    const manager = new DefaultSecureChannelManager();

    const frame = manager.generateOpenFrame("unsupported", "invalid-cipher");
    const accept = await manager.handleOpenFrame({
      ...frame,
      alg: "invalid-cipher",
    });

    expect(accept.ok).toBe(false);
    expect(accept.reason).toContain("Unsupported algorithm");
    expect(Buffer.from(accept.ephPub, "base64").length).toBe(32);
    expect(manager.hasChannel("unsupported")).toBe(false);
  });

  it("cleans up ephemeral keys when accept frames indicate rejection", async () => {
    const manager = new DefaultSecureChannelManager();
    const open = manager.generateOpenFrame("reject-me");

    const result = await manager.handleAcceptFrame({
      type: "SecureAccept",
      cid: open.cid,
      ok: false,
      reason: "peer rejected",
      ephPub: open.ephPub,
      alg: open.alg,
    });

    expect(result).toBe(false);
    expect(manager.hasChannel(open.cid)).toBe(false);
    await expect(
      manager.handleAcceptFrame({
        type: "SecureAccept",
        cid: open.cid,
        ok: true,
        ephPub: open.ephPub,
        alg: open.alg,
      })
    ).resolves.toBe(false);
  });

  it("cleans up expired channels and returns removal count", () => {
    const manager = new DefaultSecureChannelManager();
    const expiredState = {
      key: new Uint8Array(32),
      sendCounter: 0,
      receiveCounter: 0,
      noncePrefix: new Uint8Array(4),
      expiresAt: Date.now() / 1000 - 10,
      algorithm: "CHACHA20P1305",
    } as const;

    manager.addChannel("expired", expiredState as any);
    expect(manager.hasChannel("expired")).toBe(true);

    const removed = manager.cleanupExpiredChannels();
    expect(removed).toBe(1);
    expect(manager.hasChannel("expired")).toBe(false);
  });
});

describe("DefaultSecureChannelManagerFactory", () => {
  it("creates managers with custom TTL from config", async () => {
    const factory = new DefaultSecureChannelManagerFactory();
    const manager = await factory.create({
      type: "DefaultSecureChannelManager",
      channel_ttl: 120,
    });

    const peer = new DefaultSecureChannelManager();
    const channelId = "ttl-channel";
    const open = manager.generateOpenFrame(channelId);
    const accept = (await peer.handleOpenFrame(open)) as SecureAcceptFrame;

    const before = Date.now() / 1000;
    const completed = await manager.handleAcceptFrame(accept);
    expect(completed).toBe(true);

    const state = manager.channels[channelId];
    expect(state).toBeDefined();
    if (state) {
      expect(state.expiresAt).toBeGreaterThan(before + 100);
      expect(state.expiresAt).toBeLessThan(before + 150);
    }
  });
});
