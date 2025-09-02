# TypeScript DAVE Session Manager

This directory contains an example implementation of a TypeScript class capable of handling Voice Gateway events for DAVE (Discord Audio Video Encryption) support.

## Overview

The `DaveSessionManager` class can handle and respond to voice gateway events concerning DAVE.

## Features

- Voice Gateway event handling
- DAVE key ratchet generation

## Usage

1. **Initialize**: Create a `DaveSessionManager` object per selfUserId/groupId pair and call the relevant method upon receiving an opcode from the Voice Gateway.

2. **Implementation**: Look for `TODO`s and make sure to implement the relevant networking or media code.

3. **Key Updates**: Whenever you are signaled that a new key ratchet is available for a given user, make sure to update the associated encryptor/decryptor.