import type {Session, TransientKeys, DaveModule, SignaturePrivateKey} from '@discordapp/libdave/wasm';

const MLS_NEW_GROUP_EXPECTED_EPOCH = '1';
const DAVE_PROTOCOL_INIT_TRANSITION_ID = 0;

export class DaveSessionManager {
  private readonly dave: DaveModule;
  private readonly transientKeys: TransientKeys | null;
  private readonly mlsSession: Session;

  private readonly selfUserId: string;
  private readonly groupId: string;
  private readonly recognizedUserIds: Set<string> = new Set();
  private readonly daveProtocolTransitions: Map<number, number> = new Map();
  private latestPreparedTransitionVersion: number = 0;

  constructor(dave: DaveModule, transientKeys: TransientKeys | null, selfUserId: string, groupId: string) {
    this.dave = dave;
    this.transientKeys = transientKeys;
    this.selfUserId = selfUserId;
    this.groupId = groupId;

    // These are only used with persistent key storage and can be ignored most of the time
    const context = '';
    const authSessionId = '';

    this.mlsSession = new dave.Session(context, authSessionId, (source: string, reason: string) => {
      console.error(`MLS failure: ${source} ${reason}`);
    });
  }

  // Add an allowed user to the connection
  public createUser(userId: string) {
    this.recognizedUserIds.add(userId);
    this._setupKeyRatchetForUser(userId, this.latestPreparedTransitionVersion);
  }

  // Remove an allowed user from the connection
  public destroyUser(userId: string) {
    this.recognizedUserIds.delete(userId);
    // TODO: Signal the relevant media code that a user has left the call and the associated Encryptor/Decryptor should be destroyed
  }

  // Incoming Voice Gateway Requests

  // Opcode SELECT_PROTOCOL_ACK (1)
  public onSelectProtocolAck(protocolVersion: number) {
    this._handleDaveProtocolInit(protocolVersion);
  }

  // Opcode DAVE_PROTOCOL_PREPARE_TRANSITION (21)
  public onDaveProtocolPrepareTransition(transitionId: number, protocolVersion: number) {
    this._prepareDaveProtocolRatchets(transitionId, protocolVersion);
    this._maybeSendDaveProtocolReadyForTransition(transitionId);
  }

  // Opcode DAVE_PROTOCOL_EXECUTE_TRANSITION (22)
  public onDaveProtocolExecuteTransition(transitionId: number) {
    this._handleDaveProtocolExecuteTransition(transitionId);
  }

  // Opcode DAVE_PROTOCOL_PREPARE_EPOCH (24)
  public onDaveProtocolPrepareEpoch(epoch: string, protocolVersion: number) {
    this._handleDaveProtocolPrepareEpoch(epoch, protocolVersion, this.groupId);

    if (epoch === MLS_NEW_GROUP_EXPECTED_EPOCH) {
      this._sendMLSKeyPackage();
    }
  }

  // Opcode MLS_EXTERNAL_SENDER_PACKAGE (25)
  public onDaveProtocolMLSExternalSenderPackage(externalSenderPackage: ArrayBuffer) {
    this.mlsSession.SetExternalSender(externalSenderPackage);
  }

  // Opcode MLS_PROPOSALS (27)
  public onMLSProposals(proposals: ArrayBuffer) {
    const commitWelcome = this.mlsSession.ProcessProposals(proposals, this._getRecognizedUserIDs());
    if (commitWelcome) {
      this._sendMLSCommitWelcome(commitWelcome);
    }
  }

  // Opcode MLS_PREPARE_COMMIT_TRANSITION (29)
  public onMLSPrepareCommitTransition(transitionId: number, commit: ArrayBuffer) {
    const processedCommit = this.mlsSession.ProcessCommit(commit);
    const joinedGroup = processedCommit.rosterUpdate != null;

    if (processedCommit.ignored) {
      return;
    }

    if (joinedGroup) {
      this._prepareDaveProtocolRatchets(transitionId, this.mlsSession.GetProtocolVersion());
      this._maybeSendDaveProtocolReadyForTransition(transitionId);
    } else {
      this._flagMLSInvalidCommitWelcome(transitionId);
      this._handleDaveProtocolInit(this.mlsSession.GetProtocolVersion());
    }
  }

  // Opcode MLS_WELCOME (30)
  public onMLSWelcome(transitionId: number, welcome: ArrayBuffer) {
    const roster = this.mlsSession.ProcessWelcome(welcome, this._getRecognizedUserIDs());
    const joinedGroup = roster != null;

    if (joinedGroup) {
      this._prepareDaveProtocolRatchets(transitionId, this.mlsSession.GetProtocolVersion());
      this._maybeSendDaveProtocolReadyForTransition(transitionId);
    } else {
      this._flagMLSInvalidCommitWelcome(transitionId);
      this._sendMLSKeyPackage();
    }
  }

  // Outgoing Voice Gateway Responses

  // Opcode MLS_KEY_PACKAGE (26)
  private _sendMLSKeyPackage() {
    const _keyPackage = this.mlsSession.GetMarshalledKeyPackage();
    // TODO: Send keyPackage to the voice gateway using the MLS_KEY_PACKAGE (26) opcode
  }

  // Opcode DAVE_PROTOCOL_READY_FOR_TRANSITION (23)
  private _maybeSendDaveProtocolReadyForTransition(transitionId: number) {
    if (transitionId !== DAVE_PROTOCOL_INIT_TRANSITION_ID) {
      // TODO: Send the transition ready message to the voice gateway using the DAVE_PROTOCOL_READY_FOR_TRANSITION (23) opcode
    }
  }

  // Opcode MLS_COMMIT_WELCOME (28)
  private _sendMLSCommitWelcome(commitWelcomeMessage: ArrayBuffer) {
    // TODO: Send the commit welcome message to the voice gateway using the MLS_COMMIT_WELCOME (28) opcode
  }

  // Opcode MLS_INVALID_COMMIT_WELCOME (31)
  private _flagMLSInvalidCommitWelcome(transitionId: number) {
    // TODO: Send the invalid commit welcome message to the voice gateway using the MLS_INVALID_COMMIT_WELCOME (31) opcode
  }

  // Internal methods

  private _setupKeyRatchetForUser(userId: string, protocolVersion: number) {
    const keyRatchet = this._makeUserKeyRatchet(userId, protocolVersion);
    // TODO: Signal the relevant media code that a key ratchet has changed and the associated Encryptor/Decryptor needs to be updated
  }

  private _handleDaveProtocolInit(protocolVersion: number) {
    if (protocolVersion > 0) {
      this._handleDaveProtocolPrepareEpoch(MLS_NEW_GROUP_EXPECTED_EPOCH, protocolVersion, this.groupId);
      this._sendMLSKeyPackage();
    } else {
      this._prepareDaveProtocolRatchets(DAVE_PROTOCOL_INIT_TRANSITION_ID, protocolVersion);
      this._handleDaveProtocolExecuteTransition(DAVE_PROTOCOL_INIT_TRANSITION_ID);
    }
  }

  private _handleDaveProtocolPrepareEpoch(epoch: string, protocolVersion: number, groupId: string): void {
    if (epoch === MLS_NEW_GROUP_EXPECTED_EPOCH) {
      let privateKey: SignaturePrivateKey | null = null;
      if (this.transientKeys != null) {
        privateKey = this.transientKeys.GetTransientPrivateKey(protocolVersion);
      }

      this.mlsSession.Init(protocolVersion, BigInt(groupId), this.selfUserId, privateKey);
    }
  }

  private _handleDaveProtocolExecuteTransition(transitionID: number): void {
    if (!this.daveProtocolTransitions.has(transitionID)) {
      return;
    }

    const protocolVersion = this.daveProtocolTransitions.get(transitionID)!;
    this.daveProtocolTransitions.delete(transitionID);

    if (protocolVersion === this.dave.kDisabledVersion) {
      this.mlsSession.Reset();
    }

    this._setupKeyRatchetForUser(this.selfUserId, protocolVersion);
  }

  private _getRecognizedUserIDs(): string[] {
    return Array.from(this.recognizedUserIds).concat([this.selfUserId]);
  }

  private _makeUserKeyRatchet(userId: string, protocolVersion: number): any {
    if (protocolVersion === this.dave.kDisabledVersion) {
      return null;
    }

    return this.mlsSession.GetKeyRatchet(userId);
  }

  private _prepareDaveProtocolRatchets(transitionID: number, protocolVersion: number): void {
    for (const userId of this._getRecognizedUserIDs()) {
      if (userId === this.selfUserId) {
        continue;
      }

      this._setupKeyRatchetForUser(userId, protocolVersion);
    }

    if (transitionID === this.dave.kInitTransitionId) {
      this._setupKeyRatchetForUser(this.selfUserId, protocolVersion);
    } else {
      this.daveProtocolTransitions.set(transitionID, protocolVersion);
    }

    this.latestPreparedTransitionVersion = protocolVersion;
  }
}
