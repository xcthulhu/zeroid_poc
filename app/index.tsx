import { StyleSheet, TouchableOpacity } from 'react-native';
import { ThemedText } from '@/components/ThemedText';
import { ThemedView } from '@/components/ThemedView';
import NfcManager, { NfcTech } from 'react-native-nfc-manager';
import react from 'react';

import { getMRZKey } from '@/utils/passport-utils';
import { NativeModules } from "react-native";
import { base64ToUint8Array } from '@/utils/array-utils';

const { PassportNFCScanner } = NativeModules;


export default function HomeScreen() {
  const [passportData, setPassportData] = react.useState<any>(null);

  const detectPassport = async () => {
    try {
      await NfcManager.start();
      await NfcManager.requestTechnology(NfcTech.IsoDep);
      const data = await NfcManager.getTag();
      setPassportData(data);
    } catch (error) {
      console.error('Error scanning passport:', error);
    } finally {
      NfcManager.cancelTechnologyRequest();
    }
  };

  const scanPassport = async () => {
    try {
      const mrzKey = getMRZKey("591443446", "840523", "280916");
      const result = await PassportNFCScanner.scan(
        mrzKey,                  // computed mrzKey
        ["SOD", "DG1"],         // dataGroups
        true,                   // skipSecureElements
        true,                   // skipCA
        true                    // skipPACE
      );
      setPassportData(result);
    } catch (error) {
      setPassportData(`${error}`);
      console.error('Error:', error);
    }
  };

  return (
    <ThemedView style={styles.topLevelContainer}>
      <ThemedView style={styles.titleContainer}>
        <ThemedText type="title">Passport Reader</ThemedText>
      </ThemedView>
      <ThemedView style={styles.container}>
        <TouchableOpacity style={styles.button} onPress={detectPassport}>
          <ThemedText style={styles.buttonText}>Detect Passport</ThemedText>
        </TouchableOpacity>
        <TouchableOpacity style={styles.button} onPress={scanPassport}>
          <ThemedText style={styles.buttonText}>Scan Passport</ThemedText>
        </TouchableOpacity>
        {passportData && (
          <ThemedText style={styles.passportData}>
            {JSON.stringify(passportData, null, 2)}
          </ThemedText>
        )}
      </ThemedView>
    </ThemedView>
  );
}

const styles = StyleSheet.create({
  topLevelContainer: {
    flex: 1,
    alignItems: 'center',
  },
  titleContainer: {
    flexDirection: 'row',
    marginTop: 60,
    alignItems: 'center',
  },
  container: {
    flex: 1,
    alignItems: 'center',
    justifyContent: 'center',
  },
  button: {
    backgroundColor: '#007BFF',
    paddingVertical: 10,
    paddingHorizontal: 20,
    borderRadius: 10,
    marginVertical: 10,
    alignItems: 'center',
  },
  buttonText: {
    color: '#FFFFFF',
    fontSize: 16,
  },
  passportData: {
    alignSelf: 'flex-start',
    marginTop: 10,
  },
});
