import { StyleSheet, TouchableOpacity } from 'react-native';
import { ThemedText } from '@/components/ThemedText';
import { ThemedView } from '@/components/ThemedView';
import NfcManager, { NfcTech } from 'react-native-nfc-manager';
import react from 'react';

// import * as testPassportData from './passport-data.json';
import * as usCerts from '@/assets/csca/us_certs.json';
import * as passportUtils from '@/utils/passport-utils';
import { NativeModules } from "react-native";

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
      const data = await passportUtils.scan(
        "591443446",
        "840523",
        "280916",
        ["SOD", "DG1"],
      );
      // const verificationResult = await passportUtils.verifySod(testPassportData.SOD, usCerts["dddccce0b82f0ab801ae97d6b4843b6411e08925a10ac0867c33d09148798ff9-cert.der"], testPassportData.DG1, 1);
      if (!data.SOD || !data.DG1) {
        setPassportData("No data found");
        return;
      }
      const verificationResult = await passportUtils.verifySod(data.SOD, usCerts["dddccce0b82f0ab801ae97d6b4843b6411e08925a10ac0867c33d09148798ff9-cert.der"], data.DG1, 1);
      setPassportData(verificationResult);
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
