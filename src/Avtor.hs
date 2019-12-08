{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE DeriveGeneric     #-}
module Avtor where

import           Data.Text
import qualified Data.Text as T
import           Data.UUID
import           Data.UUID.V4
import           Control.Monad.IO.Class (liftIO)
import           GHC.Generics
import           Data.Aeson
import           Control.Monad.Trans.Except

type RegisterUser = RegisterReq -> IO (Either Text UnverUser)
type VerifyUser   = VerifyReq   -> IO (Either Text User)

type Login  = LoginReq  -> IO (Either Text AuthToken)
type Logout = LogoutReq -> IO (Either Text ())

type Authenticate = AuthReq -> IO (Maybe LoggedInUser)

newtype VerToken
  = VerToken
  { verToken :: UUID
  }
  deriving (Show,Generic)

newtype AuthToken = AuthToken
  { authToken :: Text
  }
  deriving (Show,Generic)

newtype UserId
  = UserId
  { userId :: UUID 
  }
  deriving (Generic,Show)

instance ToJSON UserId
instance FromJSON UserId

data User 
  = User
  { _userId   :: UserId
  , userEmail :: Text
  , userPass  :: Text
  }
  deriving (Generic,Show)

instance ToJSON User
instance FromJSON User

data UnverUser
  = UnverUser
  { uvUserId :: UserId
  , uvEmail  :: Text
  , uvPass   :: Text
  , uvToken  :: VerToken
  }

data LoggedInUser
  = LoggedInUser
  { loggedInUserId    :: UserId
  , loggedInUserEmail :: Text
  }

data RegisterDto
  = RegisterDto
  { rEmail :: Text
  , rPass  :: Text
  , rConfirmPass :: Text
  }
  deriving (Show)

data LoginDto
  = LoginDto
  { loginDtoEmail :: Text
  , loginDtoPass  :: Text
  }
  deriving (Show)

data LogoutDto = LogoutDto

data RegisterReq
  = RegisterReq
  { regDto      :: RegisterDto
  , findByEmail :: Text -> IO (Maybe User)
  , savePreUser :: UnverUser -> IO (Either Text ())
  , sendEmail   :: Text -> IO (Either Text ())
  }

(...) =  flip ($)

registerUser :: RegisterUser
registerUser req = do
  if req...regDto...rPass /= req...regDto...rConfirmPass
    then
      return $ Left "Passwords do not match"
    else do
      mayUser <- req...findByEmail $ req...regDto...rEmail
      case mayUser of
        Just _ -> return $ Left "User Exists"
        Nothing -> runExceptT $ do
          emailSentRes <- ExceptT $ req...sendEmail $ req...regDto...rEmail
          uuid         <- liftIO nextRandom
          token        <- liftIO nextRandom
          let unUser = UnverUser { uvUserId = UserId uuid, uvToken = VerToken token, uvEmail = req...regDto...rEmail , uvPass = req...regDto...rPass }
          savedUser    <- ExceptT $ req...savePreUser $ unUser
          return $ unUser


data VerifyReq
  = VerifyReq
  { vToken              :: VerToken
  , findPreuserByToken  :: VerToken  -> IO (Maybe UnverUser)
  , saveUser            :: User      -> IO (Either Text User)
  }

verifyUser :: VerifyUser
verifyUser req = do
  mayUnverifiedUser <- req...findPreuserByToken $ req...vToken
  case mayUnverifiedUser of
    Nothing -> return $ Left "Unverified user could not be found"
    Just u  -> do
      let newUser = mapUnverifiedUserToUser u
      savedUserRes <- req...saveUser $ newUser
      case savedUserRes of
        Left e  -> return $ Left e
        Right u -> return $ Right u



data LoginReq = 
  LoginReq
  { loginReqDto     :: LoginDto
  , findUserByEmail :: Text -> IO (Either Text (Maybe User))
  , matchPassword   :: Text -> Text -> Bool
  }

login :: Login
login req = do
  userOptRes <- req...findUserByEmail $ req...loginReqDto...loginDtoEmail
  case userOptRes of
    Left e          -> return $ Left e
    Right (Just u)  -> return $ Right $ AuthToken "create_auth_token"
    Right (Nothing) -> return $ Left "User not found"


data LogoutReq = LogoutReq
  { logoutReqAuthToken :: AuthToken
  , destroyAuthToken :: AuthToken -> IO (Either Text ())
  }

logout :: Logout
logout req = do
  req...destroyAuthToken $ req...logoutReqAuthToken


data AuthReq = AuthReq
  { authReqToken        :: AuthToken
  , createUserFromToken :: AuthToken -> IO (Maybe LoggedInUser)
  }

authenticate :: Authenticate
authenticate req =
  req...createUserFromToken $ req...authReqToken


mapUnverifiedUserToUser :: UnverUser -> User
mapUnverifiedUserToUser unverUser =
  User 
  { _userId   = unverUser...uvUserId
  , userEmail = unverUser...uvEmail
  , userPass  = unverUser...uvPass
  }

mapUserToLoginUser :: User -> LoggedInUser
mapUserToLoginUser user =
  LoggedInUser
  { loggedInUserId    = user..._userId
  , loggedInUserEmail = user...userEmail
  }