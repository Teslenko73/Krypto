package org.example;

import javafx.application.Platform;
import javafx.fxml.FXML;
import javafx.scene.control.*;
import javafx.stage.FileChooser;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;

public class CryptoController {

    // ── Klucze ──────────────────────────────────────────────────────────────
    @FXML private TextField publicKeyArea;
    @FXML private TextField privateKeyArea;
    @FXML private TextField modNField;
    @FXML private ProgressIndicator spinner;
    @FXML private RadioButton rb1024;
    @FXML private RadioButton rb2048;
    @FXML private ToggleGroup keySizeGroup;

    @FXML private TextField loadKeyFileField;
    @FXML private TextField saveKeyFileField;

    // ── Podpis/Weryfikacja ───────────────────────────────────────────────────
    @FXML private TextField openPlainFileField;
    @FXML private TextField openSigFileField;
    @FXML private TextField savePlainFileField;
    @FXML private TextField saveSigFileField;

    @FXML private TextArea messageArea;
    @FXML private TextArea signatureArea;

    @FXML private RadioButton modePlik;
    @FXML private RadioButton modeOkno;
    @FXML private ToggleGroup modeGroup;

    @FXML private Label statusLabel;

    // ── Stan ─────────────────────────────────────────────────────────────────
    private File selectedPlainFile = null;
    private DSAwlasny.DSAKeyPair currentKeyPair = null;

    // =========================================================================
    // GENEROWANIE KLUCZY
    // =========================================================================

    @FXML
    private void handleGenerateKeys() {
        int L = rb2048.isSelected() ? 2048 : 1024;
        int N = rb2048.isSelected() ? 256 : 160;

        setStatus("Generowanie kluczy " + L + "/" + N + "... (może potrwać kilka sekund)");
        spinner.setVisible(true);
        publicKeyArea.clear();
        privateKeyArea.clear();
        modNField.clear();
        signatureArea.clear();

        Thread t = new Thread(() -> {
            try {
                DSAwlasny dsa = new DSAwlasny(L, N);
                DSAwlasny.DSAKeyPair kp = dsa.generateKeyPair();

                Platform.runLater(() -> {
                    currentKeyPair = kp;
                    publicKeyArea.setText(kp.y.toString(16));
                    privateKeyArea.setText(kp.x.toString(16));
                    modNField.setText(kp.q.toString(16));
                    spinner.setVisible(false);
                    setStatus("Wygenerowano parę kluczy DSA " + L + "-bit.");
                });
            } catch (Exception ex) {
                Platform.runLater(() -> {
                    spinner.setVisible(false);
                    setStatus("Błąd generowania kluczy: " + ex.getMessage());
                });
            }
        });
        t.setDaemon(true);
        t.start();
    }

    // =========================================================================
    // ZAPIS / ODCZYT KLUCZY
    // =========================================================================

    @FXML
    private void handleSaveKeys() {
        if (currentKeyPair == null) {
            setStatus("Błąd: brak kluczy do zapisania. Najpierw wygeneruj klucze.");
            return;
        }
        String name = saveKeyFileField.getText().trim();
        FileChooser fc = new FileChooser();
        fc.setTitle("Zapisz klucze DSA");
        fc.setInitialFileName(name.isEmpty() ? "dsa_keys.txt" : name);
        fc.getExtensionFilters().add(new FileChooser.ExtensionFilter("Plik kluczy", "*.txt", "*.dsa"));
        File f = fc.showSaveDialog(statusLabel.getScene().getWindow());
        if (f != null) {
            try {
                String content = "PUBLIC=" + currentKeyPair.y.toString(16) + "\n"
                        + "PRIVATE=" + currentKeyPair.x.toString(16) + "\n"
                        + "P=" + currentKeyPair.p.toString(16) + "\n"
                        + "Q=" + currentKeyPair.q.toString(16) + "\n"
                        + "G=" + currentKeyPair.g.toString(16) + "\n";
                Files.writeString(f.toPath(), content, StandardCharsets.UTF_8);
                saveKeyFileField.setText(f.getName());
                setStatus("Klucze zapisane: " + f.getName());
            } catch (Exception e) {
                setStatus("Błąd zapisu: " + e.getMessage());
            }
        }
    }

    @FXML
    private void handleLoadKeys() {
        String name = loadKeyFileField.getText().trim();
        FileChooser fc = new FileChooser();
        fc.setTitle("Wczytaj klucze DSA");
        fc.getExtensionFilters().add(new FileChooser.ExtensionFilter("Plik kluczy", "*.txt", "*.dsa"));
        File f = fc.showOpenDialog(statusLabel.getScene().getWindow());
        if (f != null) {
            try {
                // Odczytaj linie w formacie KLUCZ=wartość
                java.util.Map<String, String> map = new java.util.HashMap<>();
                for (String line : Files.readAllLines(f.toPath(), StandardCharsets.UTF_8)) {
                    String[] parts = line.split("=", 2);
                    if (parts.length == 2) map.put(parts[0].trim(), parts[1].trim());
                }
                java.math.BigInteger p = new java.math.BigInteger(map.get("P"), 16);
                java.math.BigInteger q = new java.math.BigInteger(map.get("Q"), 16);
                java.math.BigInteger g = new java.math.BigInteger(map.get("G"), 16);
                java.math.BigInteger x = new java.math.BigInteger(map.get("PRIVATE"), 16);
                java.math.BigInteger y = new java.math.BigInteger(map.get("PUBLIC"), 16);

                currentKeyPair = new DSAwlasny.DSAKeyPair(p, q, g, x, y);
                publicKeyArea.setText(y.toString(16));
                privateKeyArea.setText(x.toString(16));
                modNField.setText(q.toString(16));
                loadKeyFileField.setText(f.getName());
                setStatus("Wczytano klucze z: " + f.getName());
            } catch (Exception e) {
                setStatus("Błąd odczytu kluczy: " + e.getMessage());
            }
        }
    }

    // =========================================================================
    // OTWÓRZ PLIK Z TEKSTEM JAWNYM
    // =========================================================================

    @FXML
    private void handleOpenFile() {
        FileChooser fc = new FileChooser();
        fc.setTitle("Wybierz plik z tekstem jawnym");
        File f = fc.showOpenDialog(statusLabel.getScene().getWindow());
        if (f != null) {
            selectedPlainFile = f;
            openPlainFileField.setText(f.getAbsolutePath());
            try {
                // Jeśli tryb Okno — wczytaj tekst do TextArea
                if (modeOkno.isSelected()) {
                    String content = Files.readString(f.toPath(), StandardCharsets.UTF_8);
                    messageArea.setText(content);
                } else {
                    messageArea.setText("[PLIK] " + f.getName()
                            + "  (" + f.length() + " bajtów)");
                }
                setStatus("Wczytano plik: " + f.getName());
            } catch (Exception e) {
                setStatus("Błąd odczytu pliku: " + e.getMessage());
            }
        }
    }

    // =========================================================================
    // PODPISYWANIE
    // =========================================================================

    @FXML
    private void handleSign() {
        byte[] data = getData();
        if (data == null) return;

        if (currentKeyPair == null) {
            setStatus("Błąd: brak kluczy. Wygeneruj lub wczytaj klucze.");
            return;
        }

        try {
            int N = currentKeyPair.q.bitLength() <= 160 ? 160 : 256;
            int L = currentKeyPair.p.bitLength();
            DSAwlasny dsa = new DSAwlasny(L, N);
            DSAwlasny.DSASignature sig = dsa.sign(data, currentKeyPair);
            signatureArea.setText(DSAwlasny.exportSignature(sig));
            setStatus("Podpisano pomyślnie.");
        } catch (Exception e) {
            setStatus("Błąd podpisywania: " + e.getMessage());
        }
    }

    // =========================================================================
    // WERYFIKACJA
    // =========================================================================

    @FXML
    private void handleVerify() {
        byte[] data = getData();
        if (data == null) return;

        String sigStr = signatureArea.getText().trim();
        if (sigStr.isBlank()) {
            setStatus("Błąd: brak podpisu do weryfikacji.");
            return;
        }
        if (currentKeyPair == null) {
            setStatus("Błąd: brak kluczy. Wygeneruj lub wczytaj klucze.");
            return;
        }

        try {
            DSAwlasny.DSASignature sig = DSAwlasny.importSignature(sigStr);
            DSAwlasny.DSAPublicKey pk = currentKeyPair.getPublicKey();
            int N = pk.q.bitLength() <= 160 ? 160 : 256;
            int L = pk.p.bitLength();
            DSAwlasny dsa = new DSAwlasny(L, N);

            boolean valid = dsa.verify(data, sig, pk);
            setStatus(valid
                    ? "✔ PODPIS PRAWIDŁOWY — wiadomość autentyczna."
                    : "✘ PODPIS NIEPRAWIDŁOWY — zmieniona lub zły klucz.");
        } catch (Exception e) {
            setStatus("Błąd weryfikacji: " + e.getMessage());
        }
    }

    // =========================================================================
    // WCZYTAJ PODPIS Z PLIKU
    // =========================================================================

    @FXML
    private void handleLoadSignature() {
        FileChooser fc = new FileChooser();
        fc.setTitle("Wczytaj plik z podpisem");
        fc.getExtensionFilters().add(new FileChooser.ExtensionFilter("Plik podpisu", "*.dsa", "*.txt"));
        File f = fc.showOpenDialog(statusLabel.getScene().getWindow());
        if (f != null) {
            try {
                signatureArea.setText(Files.readString(f.toPath(), StandardCharsets.UTF_8).trim());
                openSigFileField.setText(f.getAbsolutePath());
                setStatus("Wczytano podpis: " + f.getName());
            } catch (Exception e) {
                setStatus("Błąd odczytu podpisu: " + e.getMessage());
            }
        }
    }

    // =========================================================================
    // ZAPISZ TEKST JAWNY
    // =========================================================================

    @FXML
    private void handleSavePlain() {
        String text = messageArea.getText();
        if (text.isBlank()) {
            setStatus("Brak tekstu do zapisania.");
            return;
        }
        String name = savePlainFileField.getText().trim();
        FileChooser fc = new FileChooser();
        fc.setTitle("Zapisz tekst jawny");
        fc.setInitialFileName(name.isEmpty() ? "plain.txt" : name);
        File f = fc.showSaveDialog(statusLabel.getScene().getWindow());
        if (f != null) {
            try {
                Files.writeString(f.toPath(), text, StandardCharsets.UTF_8);
                savePlainFileField.setText(f.getName());
                setStatus("Tekst jawny zapisany: " + f.getName());
            } catch (Exception e) {
                setStatus("Błąd zapisu: " + e.getMessage());
            }
        }
    }

    // =========================================================================
    // ZAPISZ PODPIS
    // =========================================================================

    @FXML
    private void handleSaveSignature() {
        String sigStr = signatureArea.getText().trim();
        if (sigStr.isBlank()) {
            setStatus("Brak podpisu do zapisania.");
            return;
        }
        String name = saveSigFileField.getText().trim();
        FileChooser fc = new FileChooser();
        fc.setTitle("Zapisz podpis DSA");
        fc.setInitialFileName(name.isEmpty() ? "signature.dsa" : name);
        fc.getExtensionFilters().add(new FileChooser.ExtensionFilter("Plik podpisu", "*.dsa", "*.txt"));
        File f = fc.showSaveDialog(statusLabel.getScene().getWindow());
        if (f != null) {
            try {
                Files.writeString(f.toPath(), sigStr, StandardCharsets.UTF_8);
                saveSigFileField.setText(f.getName());
                setStatus("Podpis zapisany: " + f.getName());
            } catch (Exception e) {
                setStatus("Błąd zapisu: " + e.getMessage());
            }
        }
    }

    // =========================================================================
    // HELPERS
    // =========================================================================

    private byte[] getData() {
        // Tryb Plik: użyj wybranego pliku
        if (modePlik.isSelected() && selectedPlainFile != null) {
            try {
                return Files.readAllBytes(selectedPlainFile.toPath());
            } catch (Exception e) {
                setStatus("Błąd odczytu pliku: " + e.getMessage());
                return null;
            }
        }
        // Tryb Okno (lub brak pliku): użyj tekstu z TextArea
        String text = messageArea.getText();
        if (text.isBlank() || text.startsWith("[PLIK]")) {
            setStatus("Błąd: brak tekstu. Wpisz tekst lub wczytaj plik w trybie Okno.");
            return null;
        }
        return text.getBytes(StandardCharsets.UTF_8);
    }

    private void setStatus(String msg) {
        statusLabel.setText(msg);
    }
}

//package org.example;
//
//import javafx.fxml.FXML;
//import javafx.scene.control.RadioButton;
//import javafx.scene.control.TextArea;
//import javafx.scene.control.TextField;
//import javafx.scene.control.ToggleGroup;
//import javafx.stage.FileChooser;
//import java.io.File;
//import java.nio.charset.StandardCharsets;
//import java.nio.file.Files;
//import java.security.SecureRandom;
//import java.util.Base64;
//
//public class CryptoController {
//
//    private final AESwlasny aes = new AESwlasny();
//    private File selectedFile;
//
//    @FXML private TextArea inputField;
//    @FXML private TextField keyField;
//    @FXML private TextArea outputField;
//
//    // -----------------------------------------------------------------------
//    // GENEROWANIE KLUCZA
//    // -----------------------------------------------------------------------
//    @FXML
//    private ToggleGroup keySizeGroup;
//
//    @FXML
//    private RadioButton rb128, rb192, rb256;
//
//    // Metoda wywoływana po kliknięciu "Generuj Klucz" lub "Szyfruj"
//    private int getSelectedKeySize() {
//        if (rb256.isSelected()) return 32; // 256 bitów = 32 bajty
//        if (rb192.isSelected()) return 24; // 192 bity = 24 bajty
//        return 16;                         // Domyślnie 128 bitów = 16 bajtów
//    }
//
//    public void handleGenKey() {
//        int size = getSelectedKeySize();
//        byte[] key = new byte[size];
//        new SecureRandom().nextBytes(key);
//
//        // ZMIANA: Wyświetlamy wygenerowany klucz w polu tekstowym
//        String base64Key = Base64.getEncoder().encodeToString(key);
//        keyField.setText(base64Key);
//        outputField.setText("Wygenerowano klucz " + (size * 8) + "-bitowy.");
//    }
//    // -----------------------------------------------------------------------
//    // WYBÓR PLIKU
//    // -----------------------------------------------------------------------
//
//    @FXML
//    private void handleOpenFile() {
//        FileChooser fileChooser = new FileChooser();
//        fileChooser.setTitle("Wybierz plik");
//        File file = fileChooser.showOpenDialog(inputField.getScene().getWindow());
//        if (file != null) {
//            selectedFile = file;
//            inputField.setText("WYBRANO PLIK: " + file.getName()
//                    + "\nŚcieżka: " + file.getAbsolutePath());
//            outputField.setText("Plik gotowy. Kliknij Szyfruj lub Odszyfruj.");
//        }
//    }
//
//    // -----------------------------------------------------------------------
//    // SZYFROWANIE
//    // -----------------------------------------------------------------------
//
//    @FXML
//    private void handleEncrypt() {
//        byte[] keyBytes = parseKey();
//        if (keyBytes == null) return;
//
//        try {
//            if (selectedFile != null) {
//                encryptFile(keyBytes);
//            } else {
//                encryptText(keyBytes);
//            }
//        } catch (IllegalArgumentException e) {
//            outputField.setText("Błąd danych wejściowych: " + e.getMessage());
//        } catch (Exception e) {
//            outputField.setText("Błąd szyfrowania: " + e.getMessage());
//        }
//    }
//
//    private void encryptFile(byte[] keyBytes) throws Exception {
//        byte[] fileContent = Files.readAllBytes(selectedFile.toPath());
//        byte[] encryptedData = aes.encrypt(fileContent, keyBytes);
//
//        FileChooser saveChooser = new FileChooser();
//        saveChooser.setTitle("Zapisz zaszyfrowany plik");
//        saveChooser.setInitialFileName(selectedFile.getName() + ".enc");
//        File outFile = saveChooser.showSaveDialog(inputField.getScene().getWindow());
//
//        if (outFile != null) {
//            Files.write(outFile.toPath(), encryptedData);
//            outputField.setText("Zapisano zaszyfrowany plik: " + outFile.getName());
//        }
//        clearFileSelection();
//    }
//
//    private void encryptText(byte[] keyBytes) throws Exception {
//        String text = inputField.getText();
//        if (text.isBlank()) {
//            outputField.setText("Brak tekstu do zaszyfrowania.");
//            return;
//        }
//        byte[] encrypted = aes.encrypt(text.getBytes(StandardCharsets.UTF_8), keyBytes);
//        outputField.setText(Base64.getEncoder().encodeToString(encrypted));
//        inputField.clear();
//    }
//
//    // -----------------------------------------------------------------------
//    // DESZYFROWANIE
//    // -----------------------------------------------------------------------
//
//    @FXML
//    private void handleDecrypt() {
//        byte[] keyBytes = parseKey();
//        if (keyBytes == null) return;
//
//        try {
//            if (selectedFile != null) {
//                decryptFile(keyBytes);
//            } else {
//                decryptText(keyBytes);
//            }
//        } catch (IllegalStateException e) {
//            // Nieprawidłowy padding — prawie na pewno błędny klucz
//            outputField.setText("Błąd deszyfrowania: nieprawidłowy padding — sprawdź klucz.\n(" + e.getMessage() + ")");
//        } catch (IllegalArgumentException e) {
//            outputField.setText("Błąd danych wejściowych: " + e.getMessage());
//        } catch (Exception e) {
//            outputField.setText("Błąd deszyfrowania: " + e.getMessage());
//        }
//    }
//
//    private void decryptFile(byte[] keyBytes) throws Exception {
//        byte[] fileContent = Files.readAllBytes(selectedFile.toPath());
//        byte[] decryptedData = aes.decrypt(fileContent, keyBytes);
//
//        FileChooser saveChooser = new FileChooser();
//        saveChooser.setTitle("Zapisz odszyfrowany plik");
//        String suggestedName = selectedFile.getName()
//                .replace(".enc", "")
//                .replace(".encrypted", "");
//        saveChooser.setInitialFileName("decoded_" + suggestedName);
//        File outFile = saveChooser.showSaveDialog(inputField.getScene().getWindow());
//
//        if (outFile != null) {
//            Files.write(outFile.toPath(), decryptedData);
//            outputField.setText("Plik odszyfrowany i zapisany jako: " + outFile.getName());
//        }
//        clearFileSelection();
//    }
//
//    private void decryptText(byte[] keyBytes) throws Exception {
//        // POPRAWKA: zaszyfrowany tekst (Base64) pobieramy z outputField,
//        // ale wyraźnie pokazujemy co robimy i czyścimy po operacji.
//        String cipherBase64 = outputField.getText().replaceAll("\\s", "");
//        if (cipherBase64.isBlank()) {
//            outputField.setText("Brak zaszyfrowanego tekstu w polu wyjściowym.");
//            return;
//        }
//
//        byte[] cipherBytes;
//        try {
//            cipherBytes = Base64.getDecoder().decode(cipherBase64);
//        } catch (IllegalArgumentException e) {
//            outputField.setText("Pole wyjściowe nie zawiera prawidłowego Base64.");
//            return;
//        }
//
//        byte[] decrypted = aes.decrypt(cipherBytes, keyBytes);
//        inputField.setText(new String(decrypted, StandardCharsets.UTF_8));
//        outputField.setText("Tekst odszyfrowany — wynik w polu wejściowym.");
//    }
//
//    // -----------------------------------------------------------------------
//    // ZAPIS PLIKU (zachowana metoda szukana przez FXMLLoader)
//    // -----------------------------------------------------------------------
//
//    @FXML
//    private void handleSaveFile() {
//        outputField.setText("Info: Pliki są zapisywane automatycznie po operacji.");
//    }
//
//    // -----------------------------------------------------------------------
//    // HELPERS
//    // -----------------------------------------------------------------------
//
//    /**
//     * Parsuje i waliduje klucz z pola tekstowego.
//     * Wyświetla błąd w outputField i zwraca null gdy klucz jest nieprawidłowy.
//     */
//    private byte[] parseKey() {
//        String keyStr = keyField.getText().trim();
//        if (keyStr.isEmpty()) {
//            outputField.setText("Błąd: brak klucza. Wygeneruj klucz lub wpisz go ręcznie.");
//            return null;
//        }
//        try {
//            byte[] keyBytes = Base64.getDecoder().decode(keyStr);
//            // ZMIANA: Akceptujemy 16, 24 lub 32 bajty
//            if (keyBytes.length != 16 && keyBytes.length != 24 && keyBytes.length != 32) {
//                outputField.setText("Błąd: klucz musi mieć 16, 24 lub 32 bajty. "
//                        + "Obecna długość: " + keyBytes.length + " bajtów.");
//                return null;
//            }
//            return keyBytes;
//        } catch (IllegalArgumentException e) {
//            outputField.setText("Błąd: klucz nie jest prawidłowym Base64.");
//            return null;
//        }
//    }
//
//    private void clearFileSelection() {
//        selectedFile = null;
//        inputField.clear();
//    }
//}
