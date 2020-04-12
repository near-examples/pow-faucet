import React from 'react';
import * as nearAPIJs from 'near-api-js';
import { generateSeedPhrase } from 'near-seed-phrase';

const FaucetPrivateKey = 'ed25519:2Rtn6ms22rCRMgmGgLRSPPd6gYDCgWDuFrX6gERknSA8GKiCHE5L9Rksc1ihsSCDvMSptfbipzq29H7cDZhR1Ze3';
const FaucetName = 'meta';
const MinAccountIdLen = 2;
const MaxAccountIdLen = 64;
const ValidAccountRe = /^(([a-z\d]+[-_])*[a-z\d]+\.)*([a-z\d]+[-_])*[a-z\d]+$/;
const AuthDataKey = "meta-faucet-auth-data";

class App extends React.Component {
  constructor(props) {
    super(props);

    this.state = {
      connected: false,
      signedIn: false,
      accountId: null,
      newAccountId: "",
      creating: false,
      accountLoading: false,
      newAccountExists: false,
      computingProofOfWork: false,
    };

    this.initNear().then(() => {
      this.setState({
        connected: true,
        signedIn: !!this._authData.accountId,
        accountId: this._authData.accountId,
      })
    })
  }

  async initFaucet() {
    let key = await this._keyStore.getKey(this._nearConfig.networkId, FaucetName);
    if (!key) {
      const keyPair = nearAPIJs.KeyPair.fromString(FaucetPrivateKey);
      await this._keyStore.setKey(this._nearConfig.networkId, FaucetName, keyPair);
    }
    const account = new nearAPIJs.Account(this._near.connection, FaucetName);
    this._faucetContract =  new nearAPIJs.Contract(account, FaucetName, {
      viewMethods: ['get_min_difficulty', 'get_account_suffix', 'get_num_created_accounts'],
      changeMethods: ['create_account'],
      sender: FaucetName
    });
    this._accountSuffix = await this._faucetContract.get_account_suffix();
    this._minDifficulty = await this._faucetContract.get_min_difficulty();
    this.setState({
      numCreatedAccounts: await this._faucetContract.get_num_created_accounts(),
    });
    // console.log(JSON.stringify([...key.getPublicKey().data]));
  }

  async initNear() {
    const nearConfig = {
      networkId: 'default',
      nodeUrl: 'https://rpc.nearprotocol.com',
      contractName: FaucetName,
      walletUrl: 'https://wallet.nearprotocol.com',
    };
    const keyStore = new nearAPIJs.keyStores.BrowserLocalStorageKeyStore();
    const near = await nearAPIJs.connect(Object.assign({ deps: { keyStore } }, nearConfig));
    this._keyStore = keyStore;
    this._nearConfig = nearConfig;
    this._near = near;

    this._authData = JSON.parse(window.localStorage.getItem(AuthDataKey) || '{}');
    await this.initFaucet();
  }

  handleChange(key, value) {
    const stateChange = {
      [key]: value,
    };
    if (key === 'newAccountId') {
      value = value.toLowerCase().replace(/[^a-z0-9\-_.]/, '');
      stateChange[key] = value;
      stateChange.newAccountExists = false;
      if (this.isValidAccount(value)) {
        stateChange.accountLoading = true;
        this._near.connection.provider.query(`account/${value + this._accountSuffix}`, '').then((_a) => {
          if (this.state.newAccountId === value) {
            this.setState({
              accountLoading: false,
              newAccountExists: true,
            })
          }
        }).catch((e) => {
          if (this.state.newAccountId === value) {
            this.setState({
              accountLoading: false,
              newAccountExists: false,
            })
          }
        })
      }
    }
    this.setState(stateChange);
  }

  isValidAccount(newAccountId) {
    if (newAccountId.includes('.')) {
      return false;
    }
    const accountId = newAccountId + this._accountSuffix;
    return accountId.length >= MinAccountIdLen &&
        accountId.length <= MaxAccountIdLen &&
        accountId.match(ValidAccountRe);
  }

  newAccountClass() {
    if (!this.state.newAccountId || this.state.accountLoading) {
      return "form-control form-control-large";
    } else if (!this.state.newAccountExists && this.isValidAccount(this.state.newAccountId)) {
      return "form-control form-control-large is-valid";
    } else {
      return "form-control form-control-large is-invalid";
    }
  }

  async computeProofOfWork(accountId, publicKey) {
    let msg = [...new TextEncoder('utf-8').encode(accountId + ':')];
    // curve
    msg.push(0);
    // key
    msg.push(...publicKey.data);
    // separator
    msg.push(':'.charCodeAt(0));
    // salt
    msg.push(0, 0, 0, 0, 0, 0, 0, 0);
    msg = new Uint8Array(msg);
    const len = msg.length;
    let bestDifficulty = 0;
    for (let salt = 0; ; ++salt) {
      // compute hash
      const hashBuffer = new Uint8Array(await crypto.subtle.digest('SHA-256', msg));
      // compute number of leading zero bits
      let totalNumZeros = 0;
      for (let i = 0; i < hashBuffer.length; ++i) {
        let numZeros = Math.clz32(hashBuffer[i]) - 24;
        totalNumZeros += numZeros;
        if (numZeros < 8) {
          break;
        }
      }
      // checking difficulty
      if (totalNumZeros >= this._minDifficulty) {
        this.setState({
          computingProofOfWork: false,
        });
        return salt;
      } else if (totalNumZeros > bestDifficulty) {
        bestDifficulty = totalNumZeros;
        this.setState({
          proofOfWorkProgress: Math.trunc(bestDifficulty * 100 / this._minDifficulty),
          proofOfWorkDifficulty: bestDifficulty,
          proofOfWorkSalt: salt,
        });
      } else if (salt % 10000 === 0) {
        this.setState({
          proofOfWorkSalt: salt
        });
      }
      // incrementing salt
      for (let i = len - 8; i < len; ++i) {
        if (msg[i] === 255) {
          msg[i] = 0;
        } else {
          ++msg[i];
          break;
        }
      }
    }
  }

  async createAccount() {
    this.setState({
      creating: true,
      computingProofOfWork: true,
      proofOfWorkProgress: 0,
      proofOfWorkDifficulty: 0,
      proofOfWorkSalt: 0,
    })
    const newAccountId = this.state.newAccountId + this._accountSuffix;
    const seed = generateSeedPhrase();
    const newKeyPair = nearAPIJs.KeyPair.fromString(seed.secretKey);
    const salt = await this.computeProofOfWork(newAccountId, newKeyPair.getPublicKey());
    await this._faucetContract.create_account({
      account_id: newAccountId,
      public_key: [0, ...newKeyPair.getPublicKey().data],
      salt,
    });
    await this._keyStore.setKey(this._nearConfig.networkId, newAccountId, newKeyPair);
    this._authData = {
      accountId: newAccountId,
      seed,
    };
    window.localStorage.setItem(AuthDataKey, JSON.stringify(this._authData));
    this.setState({
      signedIn: true,
      accountId: newAccountId,
      creating: false,
      numCreatedAccounts: await this._faucetContract.get_num_created_accounts(),
    })
  }

  moveAccountToWallet() {
    window.location = `https://wallet.nearprotocol.com/recover-with-link/${this._authData.accountId}/${this._authData.seed.seedPhrase}`;
  }

  logout() {
    window.localStorage.removeItem(AuthDataKey);
    this._authData = {};
    this.setState({
      signedIn: false,
      accountId: null,
      newAccountId: "",
      creating: false,
      accountLoading: false,
      newAccountExists: false,
      computingProofOfWork: false,
    });
  }

  render() {
    const content = !this.state.connected ? (
      <div>Connecting... <span className="spinner-grow spinner-grow-sm" role="status" aria-hidden="true"></span></div>
    ) : (this.state.signedIn ? (
      <div>
        <h3>Hello, {this.state.accountId}</h3>
        <div className="form-group">
          <button
            className="btn btn-success"
            onClick={() => this.moveAccountToWallet()}
          >
            Move account to NEAR Wallet
          </button>
        </div>
        <div className="form-group">
          <button
            className="btn btn-danger"
            onClick={() => this.logout()}
          >
            Logout from Faucet
          </button>
        </div>
      </div>
    ) : (
      <div>
        <div className="form-group">
          <label htmlFor="accountId">Create a new account</label>
          <div className="input-group">
            <div className="input-group-prepend">
              <div className="input-group-text">{"@"}</div>
            </div>
            <input
              placeholder="bob"
              id="accountId"
              className={this.newAccountClass()}
              value={this.state.newAccountId}
              onChange={(e) => this.handleChange('newAccountId', e.target.value)}
              disabled={this.state.creating}
            />
            <div className="input-group-append">
              <div className="input-group-text">{this._accountSuffix}</div>
            </div>
          </div>
        </div>
        {this.state.newAccountExists && (
          <div className="alert alert-warning" role="alert">
            Account {'"' + this.state.newAccountId + this._accountSuffix + '"'} already exists!
          </div>
        )}
        <div className="form-group">
          <button
            className="btn btn-primary"
            disabled={this.state.creating || this.state.accountLoading || this.state.newAccountExists || !this.isValidAccount(this.state.newAccountId)}
            onClick={() => this.createAccount()}
          >
            {(this.state.creating || this.state.accountLoading) && (
              <span className="spinner-grow spinner-grow-sm" role="status" aria-hidden="true"></span>
            )} Create Account {this.isValidAccount(this.state.newAccountId) ? ('"' + this.state.newAccountId + this._accountSuffix + '"') : ""}
          </button>
        </div>
        {this.state.creating && (
          <div>
            {this.state.computingProofOfWork ? (
              <div>
                Computing Proof of Work. Done {this.state.proofOfWorkSalt} operations.
                <div className="progress">
                  <div className="progress-bar" role="progressbar" style={{width: this.state.proofOfWorkProgress + '%'}} aria-valuenow={this.state.proofOfWorkProgress} aria-valuemin="0"
                       aria-valuemax="100">{this.state.proofOfWorkDifficulty} out of {this._minDifficulty}
                  </div>
                </div>
              </div>
            ) : (
              <div>
                Proof of Work is Done! Creating account {'"' + this.state.newAccountId + this._accountSuffix + '"'}
              </div>
            )}
          </div>
        )}
      </div>
    ));
    return (
      <div>
        <div>
          <h1>NEAR Proof of Work Faucet</h1>
          There were <span className="font-weight-bold">{this.state.numCreatedAccounts} accounts</span> created using this faucet.
        </div>
        <hr/>
        {content}
      </div>
    );
  }
}

export default App;
