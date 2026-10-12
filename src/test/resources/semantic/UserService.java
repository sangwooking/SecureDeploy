package fixture;

class UserService {
    private UserRepository userRepository;

    public User findUser(long id) {
        return userRepository.findById(id);
    }
}
