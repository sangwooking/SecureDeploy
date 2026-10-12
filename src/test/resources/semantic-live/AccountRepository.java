package fixture;

import java.util.Optional;

interface AccountRepository {
    Optional<Account> findById(long id);
}
