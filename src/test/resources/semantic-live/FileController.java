package fixture;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
class FileController {
    @GetMapping("/api/downloads")
    public byte[] download(@RequestParam String name) throws IOException {
        Path root = Path.of("/srv/demo-downloads");
        Path requested = root.resolve(name);
        return Files.readAllBytes(requested);
    }
}
