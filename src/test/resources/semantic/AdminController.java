package fixture;

@RestController
class AdminController {
    @PreAuthorize("hasRole('ADMIN')")
    @GetMapping("/api/admin/users")
    public User findAdminUser(long id) {
        return commonAuthorization.findAuthorizedUser(id);
    }
}
