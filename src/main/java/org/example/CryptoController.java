package org.example;

import javafx.fxml.FXML;
import javafx.scene.control.TextArea;
import javafx.scene.control.TextField;
import javafx.stage.FileChooser;
import java.io.File;
import java.nio.file.Files;
import java.io.IOException;
public class CryptoController {

    @FXML
    private TextArea inputField;

    @FXML
    private TextField keyField;

    @FXML
    private TextArea outputField;
    @FXML
    private void handleOpenFile() {
        // 1. Tworzymy obiekt FileChooser
        FileChooser fileChooser = new FileChooser();
        fileChooser.setTitle("Wybierz plik tekstowy");

        // 2. Opcjonalnie: Filtrowanie plików (pokazuj tylko .txt)
        fileChooser.getExtensionFilters().add(
                new FileChooser.ExtensionFilter("Pliki tekstowe", "*.txt")
        );

        // 3. Pokazujemy okno (wymaga odniesienia do głównego okna - Stage)
        // Pobieramy stage z dowolnego elementu, np. z pola inputField
        java.io.File selectedFile = fileChooser.showOpenDialog(inputField.getScene().getWindow());

        if (selectedFile != null) {
            try {
                // 4. Czytamy zawartość pliku i wstawiamy do TextArea
                String content = java.nio.file.Files.readString(selectedFile.toPath());
                inputField.setText(content);
                System.out.println("Wczytano plik: " + selectedFile.getName());
            } catch (java.io.IOException e) {
                System.err.println("Błąd podczas czytania pliku: " + e.getMessage());
            }
        }
    }
    @FXML
    private void handleGenKey(){}
    // Metoda wywoływana po kliknięciu "ZASZYFRUJ"
    @FXML
    private void handleEncrypt() {
        String originalText = inputField.getText();
        String key = keyField.getText();

        // Tutaj wstawisz swoją logikę szyfrowania
        String result =  originalText + " (klucz: " + key + ")";
        outputField.setText(result);
    }

    // Metoda wywoływana po kliknięciu "ODSZYFRUJ"
    @FXML
    private void handleDecrypt() {
        String encryptedText = inputField.getText();
        String key = keyField.getText();

        // Tutaj wstawisz swoją logikę odszyfrowywania
        String result = "Odszyfrowano tekst kluczem: " + key;
        outputField.setText(result);
    }
}