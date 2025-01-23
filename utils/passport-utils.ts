export function getMRZKey(passportNumber: string, dateOfBirth: string, dateOfExpiry: string): string {
    const pad = (value: string, fieldLength: number): string => {
        return (value + '<'.repeat(fieldLength)).substring(0, fieldLength);
    };

    const calcCheckSum = (checkString: string): number => {
        const characterDict: { [key: string]: number } = {
            '0': 0, '1': 1, '2': 2, '3': 3, '4': 4, '5': 5, '6': 6, '7': 7, '8': 8, '9': 9,
            '<': 0, ' ': 0, 'A': 10, 'B': 11, 'C': 12, 'D': 13, 'E': 14, 'F': 15, 'G': 16,
            'H': 17, 'I': 18, 'J': 19, 'K': 20, 'L': 21, 'M': 22, 'N': 23, 'O': 24, 'P': 25,
            'Q': 26, 'R': 27, 'S': 28, 'T': 29, 'U': 30, 'V': 31, 'W': 32, 'X': 33, 'Y': 34,
            'Z': 35
        };

        const multipliers = [7, 3, 1];
        let sum = 0;
        let m = 0;

        for (const c of checkString) {
            const number = characterDict[c];
            if (number === undefined) {
                throw new Error(`Invalid character in checksum string: ${c}`);
            }
            const product = number * multipliers[m];
            sum += product;
            m = (m + 1) % 3;
        }

        return sum % 10;
    };

    try {
        const pptNr = pad(passportNumber, 9);
        const dob = pad(dateOfBirth, 6);
        const exp = pad(dateOfExpiry, 6);

        const passportNrChksum = calcCheckSum(pptNr);
        const dateOfBirthChksum = calcCheckSum(dob);
        const expiryDateChksum = calcCheckSum(exp);

        return `${pptNr}${passportNrChksum}${dob}${dateOfBirthChksum}${exp}${expiryDateChksum}`;
    } catch (error) {
        const errorMessage = error instanceof Error ? error.message : 'Unknown error occurred';
        throw new Error(`Failed to generate MRZ key: ${errorMessage}`);
    }
}