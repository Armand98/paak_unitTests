using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.IO;
using System;
using USB_Locker;

namespace UnitTestPaak
{
    [TestClass]
    public class EncryptionAndDecryptionTests
    {
        [TestMethod]
        public void RsaEncryptedTextCanBeDecrypted()
        {
            var plainText = "Hello world!";

            var RSAKeys = DataCryptography.GenerateRsaKeys();
            var encryptedText = DataCryptography.EncryptAESKey(plainText, RSAKeys.Item1);
            var decryptedText = DataCryptography.DecryptAESKey(encryptedText, RSAKeys.Item2);

            Assert.AreEqual(plainText, decryptedText);
        }

        [TestMethod]
        public void SHA512GivesTheSameHashForTheSameInput()
        {
            var plainText = "Hello world!";

            var sha512Hash1 = DataCryptography.SHA512(plainText);
            var sha512Hash2 = DataCryptography.SHA512(plainText);


            Assert.AreEqual(sha512Hash1, sha512Hash2);
        }
    }

    [TestClass]
    public class UserTests
    {
        [TestMethod]
        public void UserObjectCreatesWithParameters_GetMethodsWorksFine()
        {
            string fisrtname = "Armand";
            string lastname = "Pajor";
            string username = "Armando";
            string password = "MySecretPassword";
            string birthday = "17-04-1998";
            string question = "You favourite drink?";
            string answer = "Coffee";
            string aesKey = "MyVerySecretKey";

            var user = new User(fisrtname, lastname, username, password, birthday, question, answer, aesKey);

            Assert.AreEqual(fisrtname, user.GetFirstName());
            Assert.AreEqual(lastname, user.GetLastName());
            Assert.AreEqual(username, user.GetUsername());
            Assert.AreEqual(password, user.GetPassword());
            Assert.AreEqual(birthday, user.GetBirthday());
            Assert.AreEqual(question, user.GetQuestion());
            Assert.AreEqual(answer, user.GetAnswer());
            Assert.AreEqual(aesKey, user.GetAesKey());
        }

        [TestMethod]
        public void UserObjectCreatesWithParameters_SerMethodsWorksFine()
        {
            string fisrtname = "Armand";
            string lastname = "Pajor";
            string username = "Armando";
            string aesKey = "MyVerySecretKey";

            var user = new User(fisrtname, lastname, "", "", "", "", "", "");

            user.SetUsername(username);
            user.SetAesKey(aesKey);

            Assert.AreEqual(username, user.GetUsername());
            Assert.AreEqual(aesKey, user.GetAesKey());
        }
    }

    [TestClass]
    public class UserAuthorizationTests
    {
        [TestMethod]
        public void RegisterDataValidationWorksFineWithExpectedParameters()
        {
            string fisrtname = "Armand";
            string lastname = "Pajor";
            string username = "Armando";
            string password = "MySecretPassword98";
            string birthday = "17-04-1998";
            string question = "You favourite drink?";
            string answer = "Coffee";

            int registerValidationStatus = UserAuthentication.ValidateRegisterData(fisrtname, lastname, username, password, birthday, question, answer);

            Assert.AreEqual(0, registerValidationStatus);
        }

        [TestMethod]
        public void RegisterDataValidationCatchesEmptyParameter()
        {
            string fisrtname = "Armand";
            string lastname = "Pajor";
            string username = "Armando";
            string password = "MySecretPassword";
            string birthday = "17-04-1998";
            string question = "You favourite drink?";
            string answer = "";

            int registerValidationStatus = UserAuthentication.ValidateRegisterData(fisrtname, lastname, username, password, birthday, question, answer);

            Assert.AreEqual(1, registerValidationStatus);
        }

        [TestMethod]
        public void RegisterDataValidationCatchesUsernameIsTooShort()
        {
            string fisrtname = "Armand";
            string lastname = "Pajor";
            string username = "qt";
            string password = "MySecretPassword98";
            string birthday = "17-04-1998";
            string question = "You favourite drink?";
            string answer = "Coffee";

            int registerValidationStatus = UserAuthentication.ValidateRegisterData(fisrtname, lastname, username, password, birthday, question, answer);

            Assert.AreEqual(2, registerValidationStatus);
        }

        [TestMethod]
        public void RegisterDataValidationCatchesTooWeakPassword()
        {
            string fisrtname = "Armand";
            string lastname = "Pajor";
            string username = "Armando";
            string password = "MySecretPassword";
            string birthday = "17-04-1998";
            string question = "You favourite drink?";
            string answer = "Coffee";

            int registerValidationStatus = UserAuthentication.ValidateRegisterData(fisrtname, lastname, username, password, birthday, question, answer);

            Assert.AreEqual(3, registerValidationStatus);
        }

        [TestMethod]
        public void RegisterDataValidationCatchesPasswordWithWhiteSpaces()
        {
            string fisrtname = "Armand";
            string lastname = "Pajor";
            string username = "Armando";
            string password = "My Secret Password 98";
            string birthday = "17-04-1998";
            string question = "You favourite drink?";
            string answer = "Coffee";

            int registerValidationStatus = UserAuthentication.ValidateRegisterData(fisrtname, lastname, username, password, birthday, question, answer);

            Assert.AreEqual(4, registerValidationStatus);
        }

        [TestMethod]
        public void RegisterDataValidationCatchesWrongDateFormat()
        {
            string fisrtname = "Armand";
            string lastname = "Pajor";
            string username = "Armando";
            string password = "MySecretPassword98";
            string birthday = "17/04/1998";
            string question = "You favourite drink?";
            string answer = "Coffee";

            int registerValidationStatus = UserAuthentication.ValidateRegisterData(fisrtname, lastname, username, password, birthday, question, answer);

            Assert.AreEqual(5, registerValidationStatus);
        }
    }
}
