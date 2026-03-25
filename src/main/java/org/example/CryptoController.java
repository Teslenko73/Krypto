package org.example;

import javafx.fxml.FXML;
import javafx.scene.control.TextArea;
import javafx.scene.control.TextField;
import javafx.stage.FileChooser;
import java.io.File;
import java.nio.file.Files;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

public class CryptoController {
    private final AES aes = new AES();

    @FXML
    private TextArea inputField;

    @FXML
    private TextField keyField;

    @FXML
    private TextArea outputField;
    @FXML
    private void handleOpenFile() {
        FileChooser fileChooser = new FileChooser();
        fileChooser.setTitle("Wybierz dowolny plik");

        // Dodajemy filtr "Wszystkie pliki"
        fileChooser.getExtensionFilters().add(
                new FileChooser.ExtensionFilter("Wszystkie pliki", "*.*")
        );

        File selectedFile = fileChooser.showOpenDialog(inputField.getScene().getWindow());

        if (selectedFile != null) {
            try {
                // Czytamy surowe bajty pliku
                byte[] bytes = Files.readAllBytes(selectedFile.toPath());

                // Opcja A: Wczytanie jako tekst (może "psuć" pliki binarne przy zapisie)
                // String content = new String(bytes, java.nio.charset.StandardCharsets.UTF_8);

                // Opcja B: Bezpieczniejsza dla obrazów/plików binarnych - Base64
                String content = java.util.Base64.getEncoder().encodeToString(bytes);

                inputField.setText(content);
                System.out.println("Wczytano: " + selectedFile.getName());
            } catch (IOException e) {
                outputField.setText("Błąd odczytu: " + e.getMessage());
            }
        }
    }

    @FXML
    private void handleSaveFile() {
        String contentToSave = outputField.getText();
        if (contentToSave.isEmpty()) return;

        FileChooser fileChooser = new FileChooser();
        fileChooser.setTitle("Zapisz plik");

        // Brak filtrów spowoduje, że użytkownik sam wpisuje pełną nazwę (np. "moj_plik")
        File file = fileChooser.showSaveDialog(outputField.getScene().getWindow());

        if (file != null) {
            try {
                String content = outputField.getText().trim();
                try {
                    // Próbujemy odkodować (zadziała tylko dla "czystego" Base64 bez spacji)
                    byte[] decodedBytes = java.util.Base64.getDecoder().decode(content);
                    Files.write(file.toPath(), decodedBytes);
                } catch (IllegalArgumentException e) {
                    // Jeśli to nie był Base64 (bo były spacje), zapisujemy jako zwykły tekst
                    Files.writeString(file.toPath(), content);
                }

                System.out.println("Zapisano: " + file.getAbsolutePath());
            } catch (Exception e) {
                outputField.setText("write error: " + e.getMessage());
            }
        }
    }
    @FXML
    private void handleGenKey(){

        // Pobieramy surowe bajty z Twojej nowej metody
        byte[] surowyKlucz = aes.generowanieklucza();

        // Konwertujemy je na String tylko na potrzeby wyświetlenia w TextField
        String kluczDoPola = Base64.getEncoder().encodeToString(surowyKlucz);

        keyField.setText(kluczDoPola);

    }
    // Metoda wywoływana po kliknięciu "ZASZYFRUJ"
    @FXML
    private void handleEncrypt() {
        String originalText = inputField.getText();
        String key = keyField.getText();

        // Tutaj wstawisz swoją logikę szyfrowania
        // String result =  originalText + " (klucz: " + key + ")";
        outputField.setText(originalText);
    }

    // Metoda wywoływana po kliknięciu "ODSZYFRUJ"
    @FXML
    private void handleDecrypt() {
        String encryptedText = inputField.getText();
        String key = keyField.getText();

        // Tutaj wstawisz swoją logikę odszyfrowywania
        String result = "gratulacje uzytkowniku odszyfrowales cos tam";
        outputField.setText(result);
    }
}