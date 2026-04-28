package org.example;

import javafx.fxml.FXML;
import javafx.scene.control.RadioButton;
import javafx.scene.control.TextArea;
import javafx.scene.control.TextField;
import javafx.scene.control.ToggleGroup;
import javafx.stage.FileChooser;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.SecureRandom;
import java.util.Base64;

public class CryptoController {

    private final AESwlasny aes = new AESwlasny();
    private File selectedFile;

    @FXML private TextArea inputField;
    @FXML private TextField keyField;
    @FXML private TextArea outputField;

    // -----------------------------------------------------------------------
    // GENEROWANIE KLUCZA
    // -----------------------------------------------------------------------
    @FXML
    private ToggleGroup keySizeGroup;

    @FXML
    private RadioButton rb128, rb192, rb256;

    // Metoda wywoływana po kliknięciu "Generuj Klucz" lub "Szyfruj"
    private int getSelectedKeySize() {
        if (rb256.isSelected()) return 32; // 256 bitów = 32 bajty
        if (rb192.isSelected()) return 24; // 192 bity = 24 bajty
        return 16;                         // Domyślnie 128 bitów = 16 bajtów
    }

    public void handleGenKey() {
        int size = getSelectedKeySize();
        byte[] key = new byte[size];
        new SecureRandom().nextBytes(key);

        // ZMIANA: Wyświetlamy wygenerowany klucz w polu tekstowym
        String base64Key = Base64.getEncoder().encodeToString(key);
        keyField.setText(base64Key);
        outputField.setText("Wygenerowano klucz " + (size * 8) + "-bitowy.");
    }
    // -----------------------------------------------------------------------
    // WYBÓR PLIKU
    // -----------------------------------------------------------------------

    @FXML
    private void handleOpenFile() {
        FileChooser fileChooser = new FileChooser();
        fileChooser.setTitle("Wybierz plik");
        File file = fileChooser.showOpenDialog(inputField.getScene().getWindow());
        if (file != null) {
            selectedFile = file;
            inputField.setText("WYBRANO PLIK: " + file.getName()
                    + "\nŚcieżka: " + file.getAbsolutePath());
            outputField.setText("Plik gotowy. Kliknij Szyfruj lub Odszyfruj.");
        }
    }

    // -----------------------------------------------------------------------
    // SZYFROWANIE
    // -----------------------------------------------------------------------

    @FXML
    private void handleEncrypt() {
        byte[] keyBytes = parseKey();
        if (keyBytes == null) return;

        try {
            if (selectedFile != null) {
                encryptFile(keyBytes);
            } else {
                encryptText(keyBytes);
            }
        } catch (IllegalArgumentException e) {
            outputField.setText("Błąd danych wejściowych: " + e.getMessage());
        } catch (Exception e) {
            outputField.setText("Błąd szyfrowania: " + e.getMessage());
        }
    }

    private void encryptFile(byte[] keyBytes) throws Exception {
        byte[] fileContent = Files.readAllBytes(selectedFile.toPath());
        byte[] encryptedData = aes.encrypt(fileContent, keyBytes);

        FileChooser saveChooser = new FileChooser();
        saveChooser.setTitle("Zapisz zaszyfrowany plik");
        saveChooser.setInitialFileName(selectedFile.getName() + ".enc");
        File outFile = saveChooser.showSaveDialog(inputField.getScene().getWindow());

        if (outFile != null) {
            Files.write(outFile.toPath(), encryptedData);
            outputField.setText("Zapisano zaszyfrowany plik: " + outFile.getName());
        }
        clearFileSelection();
    }

    private void encryptText(byte[] keyBytes) throws Exception {
        String text = inputField.getText();
        if (text.isBlank()) {
            outputField.setText("Brak tekstu do zaszyfrowania.");
            return;
        }
        byte[] encrypted = aes.encrypt(text.getBytes(StandardCharsets.UTF_8), keyBytes);
        outputField.setText(Base64.getEncoder().encodeToString(encrypted));
        inputField.clear();
    }

    // -----------------------------------------------------------------------
    // DESZYFROWANIE
    // -----------------------------------------------------------------------

    @FXML
    private void handleDecrypt() {
        byte[] keyBytes = parseKey();
        if (keyBytes == null) return;

        try {
            if (selectedFile != null) {
                decryptFile(keyBytes);
            } else {
                decryptText(keyBytes);
            }
        } catch (IllegalStateException e) {
            // Nieprawidłowy padding — prawie na pewno błędny klucz
            outputField.setText("Błąd deszyfrowania: nieprawidłowy padding — sprawdź klucz.\n(" + e.getMessage() + ")");
        } catch (IllegalArgumentException e) {
            outputField.setText("Błąd danych wejściowych: " + e.getMessage());
        } catch (Exception e) {
            outputField.setText("Błąd deszyfrowania: " + e.getMessage());
        }
    }

    private void decryptFile(byte[] keyBytes) throws Exception {
        byte[] fileContent = Files.readAllBytes(selectedFile.toPath());
        byte[] decryptedData = aes.decrypt(fileContent, keyBytes);

        FileChooser saveChooser = new FileChooser();
        saveChooser.setTitle("Zapisz odszyfrowany plik");
        String suggestedName = selectedFile.getName()
                .replace(".enc", "")
                .replace(".encrypted", "");
        saveChooser.setInitialFileName("decoded_" + suggestedName);
        File outFile = saveChooser.showSaveDialog(inputField.getScene().getWindow());

        if (outFile != null) {
            Files.write(outFile.toPath(), decryptedData);
            outputField.setText("Plik odszyfrowany i zapisany jako: " + outFile.getName());
        }
        clearFileSelection();
    }

    private void decryptText(byte[] keyBytes) throws Exception {
        // POPRAWKA: zaszyfrowany tekst (Base64) pobieramy z outputField,
        // ale wyraźnie pokazujemy co robimy i czyścimy po operacji.
        String cipherBase64 = outputField.getText().replaceAll("\\s", "");
        if (cipherBase64.isBlank()) {
            outputField.setText("Brak zaszyfrowanego tekstu w polu wyjściowym.");
            return;
        }

        byte[] cipherBytes;
        try {
            cipherBytes = Base64.getDecoder().decode(cipherBase64);
        } catch (IllegalArgumentException e) {
            outputField.setText("Pole wyjściowe nie zawiera prawidłowego Base64.");
            return;
        }

        byte[] decrypted = aes.decrypt(cipherBytes, keyBytes);
        inputField.setText(new String(decrypted, StandardCharsets.UTF_8));
        outputField.setText("Tekst odszyfrowany — wynik w polu wejściowym.");
    }

    // -----------------------------------------------------------------------
    // ZAPIS PLIKU (zachowana metoda szukana przez FXMLLoader)
    // -----------------------------------------------------------------------

    @FXML
    private void handleSaveFile() {
        outputField.setText("Info: Pliki są zapisywane automatycznie po operacji.");
    }

    // -----------------------------------------------------------------------
    // HELPERS
    // -----------------------------------------------------------------------

    /**
     * Parsuje i waliduje klucz z pola tekstowego.
     * Wyświetla błąd w outputField i zwraca null gdy klucz jest nieprawidłowy.
     */
    private byte[] parseKey() {
        String keyStr = keyField.getText().trim();
        if (keyStr.isEmpty()) {
            outputField.setText("Błąd: brak klucza. Wygeneruj klucz lub wpisz go ręcznie.");
            return null;
        }
        try {
            byte[] keyBytes = Base64.getDecoder().decode(keyStr);
            // ZMIANA: Akceptujemy 16, 24 lub 32 bajty
            if (keyBytes.length != 16 && keyBytes.length != 24 && keyBytes.length != 32) {
                outputField.setText("Błąd: klucz musi mieć 16, 24 lub 32 bajty. "
                        + "Obecna długość: " + keyBytes.length + " bajtów.");
                return null;
            }
            return keyBytes;
        } catch (IllegalArgumentException e) {
            outputField.setText("Błąd: klucz nie jest prawidłowym Base64.");
            return null;
        }
    }

    private void clearFileSelection() {
        selectedFile = null;
        inputField.clear();
    }
}
