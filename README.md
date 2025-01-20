# ZeroID Phone App

Welcome to the **ZeroID Phone App**! This Expo-based app supports `zeroid://` URL handlers, requiring iOS-specific development. Below are instructions to get you started developing on for **iOS**.

---

## Getting Started

Before running the app, ensure you have all dependencies installed. Start by running:

```bash
npm install
```

This will install the necessary packages and dependencies for the project.

---

## Bundle the Expo App

To bundle the `expo` app, type:

```bash
npx expo export
```

---

## Tips for Getting a Clean Build

Sometimes there can be issues with npm cache and misconfigured build directories.

To make a completely clean build, type the following:

```bash
git clean -Xdf
npm cache clean --force
npm install
npx expo export
```

After this, the Expo app should be successfully bundled.


---

## Running the App on the iOS Simulator

Since the app registers `zeroid://` URL handlers, you need to use the iOS Simulator for testing. Follow these steps:

1. Prebuild the iOS native files:

```bash
npx expo prebuild
```

2. Install the required CocoaPods:

```bash
npx pod-install
```

3. Launch the app on the iOS Simulator:

```bash
npx expo run:ios
```

### Testing URL Handlers in the iOS Simulator

To open a `zeroid://` URL (e.g., to test a specific functionality), use the following command:

```bash
xcrun simctl openurl booted "zeroid://prover?sessionId=123456"
```

Replace `123456` with your desired session ID or other query parameters.

---

## Deploying to a Physical iPhone

### Prerequisites

To deploy to a physical iPhone, you must have:

- An **Apple Developer Membership**.
- Access to your phone's **UDID** (Unique Device Identifier).

#### Steps to Add Your iPhone to Your Developer Account

1. **Find Your iPhone's UDID**:
   - Connect your iPhone to your Mac.
   - Open **Finder** and locate your phone under **Locations**.
   - Click on your phone, then repeatedly click the small text displaying the model, available storage, and battery percentage until the **UDID** appears.
   - Copy the UDID.

2. **Register Your iPhone**:
   - Visit [Apple's Developer Portal](https://developer.apple.com/account/resources/devices/list).
   - Add your iPhone and enter its UDID.

### Building and Installing the App

1. Open the `ZeroID.xcodeproj` file located in the `ios` directory. You can do this at the command line by typing

   ```bash
   open ios/ZeroID.xcodeproj
   ```

   This will open **Xcode**.

2. In Xcode:
   - Select the `ZeroID` project under **Targets**.
   - Go to the **Signing and Capabilities** tab.
   - Log in to your Apple Developer account and set your team.

3. Once the setup in Xcode is complete, return to the terminal and run:

   ```bash
   npx react-native run-ios --mode Release --terminal terminal
   ```

   If all goes well, the app will be installed on your iPhone.