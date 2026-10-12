package fixture;

import org.springframework.stereotype.Service;

@Service
class AccountService {
    private final AccountRepository accountRepository;

    AccountService(AccountRepository accountRepository) {
        this.accountRepository = accountRepository;
    }

    public Account findAccount(long id) {
        return accountRepository.findById(id).orElseThrow();
    }
}
