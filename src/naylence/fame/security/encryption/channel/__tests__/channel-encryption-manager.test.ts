import { createFameEnvelope, FameAddress, formatAddress } from "@naylence/core";
import type {
  DataFrame,
  DeliveryAckFrame,
  SecureOpenFrame,
} from "@naylence/core";
import { ChannelEncryptionManager } from "../channel-encryption-manager.js";

type TestSecureChannelState = {
  key: Uint8Array;
  sendCounter: number;
  receiveCounter: number;
  noncePrefix: Uint8Array;
  expiresAt: number;
  algorithm: string;
};

function createSecureChannelState(): TestSecureChannelState {
  return {
    key: new Uint8Array(32).fill(5),
    sendCounter: 0,
    receiveCounter: 0,
    noncePrefix: new Uint8Array(4).fill(7),
    expiresAt: Date.now() + 60_000,
    algorithm: "CHACHA20P1305",
  };
}

function createSecureChannelManager(
  channels: Record<string, TestSecureChannelState>,
): any {
  return {
    channels,
    generateOpenFrame: jest.fn(
      (channelId: string): SecureOpenFrame => ({
        type: "SecureOpen",
        cid: channelId,
        ephPub: "AAA=".repeat(8).slice(0, 44),
        alg: "CHACHA20P1305",
        opts: 0,
      }),
    ),
    handleOpenFrame: jest.fn(),
    handleAcceptFrame: jest.fn(),
    handleCloseFrame: jest.fn(),
    isChannelEncrypted: jest.fn().mockReturnValue(true),
    hasChannel: jest.fn((channelId: string) => Boolean(channels[channelId])),
    getChannelInfo: jest.fn(),
    closeChannel: jest.fn(),
    cleanupExpiredChannels: jest.fn(),
    addChannel: jest.fn((channelId: string, state: TestSecureChannelState) => {
      channels[channelId] = state;
    }),
    removeChannel: jest.fn((channelId: string) => delete channels[channelId]),
  };
}

function createDataEnvelope(payload: unknown, to: FameAddress) {
  const frame: DataFrame = {
    type: "Data",
    payload,
    codec: "json",
  };

  return createFameEnvelope({
    frame,
    to,
    replyTo: formatAddress("reply", "/inbox"),
  });
}

function hexToBase64(hex: string): string {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.slice(i, i + 2), 16);
  }
  return Buffer.from(bytes).toString("base64");
}

async function waitForMicrotask(): Promise<void> {
  await new Promise((resolve) => setTimeout(resolve, 0));
}

describe("ChannelEncryptionManager", () => {
  it("encrypts and decrypts envelopes when channel is available", async () => {
    const destination = new FameAddress("svc@/secure");
    const channelId = `auto-${destination.toString()}-1234`;
    const channels: Record<string, TestSecureChannelState> = {
      [channelId]: createSecureChannelState(),
    };
    const secureChannelManager = createSecureChannelManager(channels);

    const manager = new ChannelEncryptionManager({ secureChannelManager });
    const envelope = createDataEnvelope({ message: "hello" }, destination);

    const result = await manager.encryptEnvelope(envelope, { destination });
    expect(result.envelope).toBeDefined();
    expect(result.envelope?.frame.codec).toBe("b64");
    expect(result.envelope?.sec?.enc?.kid).toBe(channelId);

    const encHeader = result.envelope?.sec?.enc;
    if (encHeader?.val) {
      encHeader.val = hexToBase64(encHeader.val);
    }

    const decrypted = await manager.decryptEnvelope(result.envelope!);
    expect(decrypted.frame.payload).toEqual({ message: "hello" });
    expect(decrypted.frame.codec).toBe("json");
    expect(decrypted.sec).toBeUndefined();
  });

  it("queues envelopes, performs handshake, and delivers once channel is ready", async () => {
    const destination = new FameAddress("svc@/queued");
    const channels: Record<string, TestSecureChannelState> = {};
    const secureChannelManager = createSecureChannelManager(channels);

    const deliveredEnvelopes: any[] = [];
    const nodeLike = {
      sid: "node-1",
      physicalPath: "/root/node",
      envelopeFactory: {
        createEnvelope: createFameEnvelope,
      },
      deliver: jest.fn(async (env: any) => {
        deliveredEnvelopes.push(env);
      }),
    } as any;

    const spawnCalls: Array<(signal?: AbortSignal) => Promise<unknown>> = [];
    const activeTasks: Promise<unknown>[] = [];
    const taskSpawner = {
      spawn: <T>(fn: (signal?: AbortSignal) => Promise<T>) => {
        spawnCalls.push(fn);
        const promise = fn();
        activeTasks.push(promise);
        return {
          id: `task-${spawnCalls.length}`,
          name: "task",
          promise,
          abortController: new AbortController(),
          startTime: Date.now(),
          cancel: jest.fn(),
          isCancelled: jest.fn().mockReturnValue(false),
          isCompleted: jest.fn().mockReturnValue(true),
          isFailed: jest.fn().mockReturnValue(false),
        };
      },
    };

    const flushTasks = async () => {
      if (activeTasks.length === 0) {
        return;
      }
      const tasks = [...activeTasks];
      activeTasks.length = 0;
      await Promise.all(tasks);
    };

    const manager = new ChannelEncryptionManager({
      secureChannelManager,
      nodeLike,
      taskSpawner,
    });

    const envelope = createDataEnvelope({ batch: 1 }, destination);
    const result = await manager.encryptEnvelope(envelope, { destination });
    expect(result.status).toBe("QUEUED");
    expect(spawnCalls).toHaveLength(1);

    await flushTasks();

    const openFrameCall = (secureChannelManager.generateOpenFrame as jest.Mock)
      .mock.calls[0];
    const channelId: string = openFrameCall[0];
    expect(channelId.startsWith(`auto-${destination}-`)).toBe(true);

    channels[channelId] = createSecureChannelState();
    await manager.notifyChannelEstablished(channelId);
    await flushTasks();

    expect(nodeLike.deliver).toHaveBeenCalledTimes(1);
    expect(deliveredEnvelopes).toHaveLength(1);
    const encryptedEnvelope = deliveredEnvelopes[0];
    expect(encryptedEnvelope.frame.codec).toBe("b64");
    expect(encryptedEnvelope.sec.enc.kid).toBe(channelId);
  });

  it("sends delivery NACK when channel establishment fails", async () => {
    const destination = new FameAddress("svc@/failure");
    const secureChannelManager = createSecureChannelManager({});

    const nackEnvelopes: DeliveryAckFrame[] = [];
    const nodeLike = {
      sid: "node-2",
      envelopeFactory: {
        createEnvelope: createFameEnvelope,
      },
      deliver: jest.fn(async (env: any) => {
        if (env.frame?.type === "DeliveryAck") {
          nackEnvelopes.push(env.frame as DeliveryAckFrame);
        }
      }),
    } as any;

    const manager = new ChannelEncryptionManager({
      secureChannelManager,
      nodeLike,
    });

    const envelope = createDataEnvelope({ payload: true }, destination);
    const queued = await manager.encryptEnvelope(envelope, { destination });
    expect(queued.status).toBe("QUEUED");

    await waitForMicrotask();

    const channelId = `auto-${destination.toString()}-pending`;
    await manager.notifyChannelFailed(channelId, "timeout");

    await waitForMicrotask();

    expect(nodeLike.deliver).toHaveBeenCalledTimes(1);
    expect(nackEnvelopes).toHaveLength(1);
    expect(nackEnvelopes[0]).toMatchObject({
      ok: false,
      code: "channel_handshake_failed",
    });
  });
});
