import {
    type FameEnvelope,
    type SecureOpenFrame,
    formatAddress,
    generateId,
} from "naylence-core";

import type { NodeLike } from "naylence-runtime";

import { DefaultSecureChannelManager } from "../default-secure-channel-manager.js";
import { ChannelEncryptionManager } from "../channel/channel-encryption-manager.js";

async function flushAsyncTasks(): Promise<void> {
    await new Promise((resolve) => {
        setImmediate(resolve);
    });
}

describe("ChannelEncryptionManager integration", () => {
    it("performs a full secure-channel handshake and round-trips payload encryption", async () => {
        const senderSecureChannels = new DefaultSecureChannelManager();
        const receiverSecureChannels = new DefaultSecureChannelManager();

        const destinationAddress = formatAddress("svc", "/integration");
        const envelopePayload = { greeting: "hello", id: 42 } as const;

        const delivered: Array<{ envelope: FameEnvelope; context: unknown }> = [];

        const nodeLike = {
            sid: "child-node",
            physicalPath: "/child",
            envelopeFactory: {
                createEnvelope: jest.fn(
                    ({
                        to,
                        frame,
                        replyTo,
                        corrId,
                    }: {
                        to: FameEnvelope["to"];
                        frame: FameEnvelope["frame"];
                        replyTo?: FameEnvelope["replyTo"];
                        corrId?: string;
                    }): FameEnvelope => ({
                        id: generateId(),
                        to,
                        frame,
                        replyTo,
                        corrId,
                    })
                ),
            },
            deliver: jest.fn(async (envelope: FameEnvelope, context: unknown) => {
                delivered.push({ envelope, context });
            }),
        } as unknown as NodeLike;

        const senderManager = new ChannelEncryptionManager({
            secureChannelManager: senderSecureChannels,
            nodeLike,
        });

        const outboundEnvelope: FameEnvelope = {
            id: generateId(),
            to: destinationAddress,
            frame: {
                type: "Data",
                codec: "json",
                payload: envelopePayload,
            },
            sec: {},
        } as FameEnvelope;

        await senderManager.encryptEnvelope(outboundEnvelope);

        await flushAsyncTasks();
        expect(delivered).toHaveLength(1);
        const openDelivery = delivered[0];
        const openFrame = openDelivery.envelope.frame as SecureOpenFrame;
        expect(openFrame?.type).toBe("SecureOpen");
        expect(openDelivery.envelope.replyTo?.toString()).toContain("__sys__");

        const channelId = (openFrame as { cid?: string }).cid;
        expect(typeof channelId).toBe("string");

        const acceptFrame = await receiverSecureChannels.handleOpenFrame(openFrame);
        expect(acceptFrame.ok).toBe(true);

        const completed = await senderSecureChannels.handleAcceptFrame(acceptFrame);
        expect(completed).toBe(true);
        expect(senderSecureChannels.hasChannel(channelId!)).toBe(true);
        expect(receiverSecureChannels.hasChannel(channelId!)).toBe(true);

        await senderManager.notifyChannelEstablished(channelId!);
        await flushAsyncTasks();

        expect(delivered).toHaveLength(2);
        const dataDelivery = delivered[1];
        expect(dataDelivery.envelope.frame?.type).toBe("Data");
        expect(dataDelivery.envelope.frame?.codec).toBe("b64");
        expect(typeof dataDelivery.envelope.frame?.payload).toBe("string");
        expect(dataDelivery.envelope.sec?.enc?.alg).toBe("chacha20-poly1305-channel");
        expect(dataDelivery.envelope.sec?.enc?.kid).toBe(channelId);

        const inboundEnvelope = dataDelivery.envelope;
        if (inboundEnvelope.sec?.enc?.val) {
            const nonceBytes = Buffer.from(inboundEnvelope.sec.enc.val, "hex");
            inboundEnvelope.sec.enc.val = Buffer.from(nonceBytes).toString("base64");
        }
        const receiverManager = new ChannelEncryptionManager({
            secureChannelManager: receiverSecureChannels,
        });

        const decryptedEnvelope = await receiverManager.decryptEnvelope(inboundEnvelope);

        expect(decryptedEnvelope.frame?.codec).toBe("json");
        expect((decryptedEnvelope.frame as { payload?: unknown })?.payload).toEqual(envelopePayload);
        expect(decryptedEnvelope.sec?.enc).toBeUndefined();
    });

    it("queues the first send, then encrypts and delivers subsequent channel messages", async () => {
        const senderSecureChannels = new DefaultSecureChannelManager();
        const receiverSecureChannels = new DefaultSecureChannelManager();

        const systemInbox = formatAddress("__sys__", "/parent");
        const firstPayload = { greeting: "handshake", step: 1 } as const;
        const secondPayload = { greeting: "channel", step: 2 } as const;

        const delivered: Array<{ envelope: FameEnvelope; context: unknown }> = [];

        const nodeLike = {
            sid: "child-node",
            physicalPath: "/child",
            envelopeFactory: {
                createEnvelope: jest.fn(
                    ({
                        to,
                        frame,
                        replyTo,
                        corrId,
                    }: {
                        to: FameEnvelope["to"];
                        frame: FameEnvelope["frame"];
                        replyTo?: FameEnvelope["replyTo"];
                        corrId?: string;
                    }): FameEnvelope => ({
                        id: generateId(),
                        to,
                        frame,
                        replyTo,
                        corrId,
                    })
                ),
            },
            deliver: jest.fn(async (envelope: FameEnvelope, context: unknown) => {
                delivered.push({ envelope, context });
            }),
        } as unknown as NodeLike;

        const senderManager = new ChannelEncryptionManager({
            secureChannelManager: senderSecureChannels,
            nodeLike,
        });

        const receiverManager = new ChannelEncryptionManager({
            secureChannelManager: receiverSecureChannels,
        });

        const firstEnvelope: FameEnvelope = {
            id: generateId(),
            to: systemInbox,
            frame: {
                type: "Data",
                codec: "json",
                payload: firstPayload,
            },
            sec: {},
        } as FameEnvelope;

        await senderManager.encryptEnvelope(firstEnvelope);

        await flushAsyncTasks();
        expect(delivered).toHaveLength(1);
        const openDelivery = delivered[0];
        const openFrame = openDelivery.envelope.frame as SecureOpenFrame;
        expect(openFrame.type).toBe("SecureOpen");

        const channelId = openFrame.cid;
        expect(typeof channelId).toBe("string");

        const acceptFrame = await receiverSecureChannels.handleOpenFrame(openFrame);
        expect(acceptFrame.ok).toBe(true);

        const completed = await senderSecureChannels.handleAcceptFrame(acceptFrame);
        expect(completed).toBe(true);

        await senderManager.notifyChannelEstablished(channelId!);
        await flushAsyncTasks();

        expect(delivered).toHaveLength(2);
        const handshakeDelivery = delivered[1];
        expect(handshakeDelivery.envelope.frame?.type).toBe("Data");
        expect(handshakeDelivery.envelope.sec?.enc?.kid).toBe(channelId);

        const queuedEnvelope = handshakeDelivery.envelope;
        if (queuedEnvelope.sec?.enc?.val) {
            const nonceBytes = Buffer.from(queuedEnvelope.sec.enc.val, "hex");
            queuedEnvelope.sec.enc.val = Buffer.from(nonceBytes).toString("base64");
        }

        const decryptedQueued = await receiverManager.decryptEnvelope(queuedEnvelope);
        expect((decryptedQueued.frame as { payload?: unknown })?.payload).toEqual(firstPayload);

        delivered.length = 0;

        const immediateEnvelope: FameEnvelope = {
            id: generateId(),
            to: systemInbox,
            frame: {
                type: "Data",
                codec: "json",
                payload: secondPayload,
            },
            sec: {},
        } as FameEnvelope;

        await senderManager.encryptEnvelope(immediateEnvelope);

        expect(immediateEnvelope.frame?.codec).toBe("b64");
        expect(immediateEnvelope.sec?.enc?.alg).toBe("chacha20-poly1305-channel");
        expect(immediateEnvelope.sec?.enc?.kid).toBe(channelId);

        if (immediateEnvelope.sec?.enc?.val) {
            const nonceBytes = Buffer.from(immediateEnvelope.sec.enc.val, "hex");
            immediateEnvelope.sec.enc.val = Buffer.from(nonceBytes).toString("base64");
        }

        const decryptedImmediate = await receiverManager.decryptEnvelope(immediateEnvelope);
        expect(decryptedImmediate.frame?.codec).toBe("json");
        expect((decryptedImmediate.frame as { payload?: unknown })?.payload).toEqual(secondPayload);
        expect(decryptedImmediate.sec?.enc).toBeUndefined();
    });
});
