package fixture;

@RestController
class FileController {
    @GetMapping("/api/files")
    public byte[] readFile(String name) throws Exception {
        return Files.readAllBytes(Path.of(name));
    }
}
