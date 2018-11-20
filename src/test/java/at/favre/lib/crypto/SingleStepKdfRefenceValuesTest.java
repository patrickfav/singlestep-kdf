package at.favre.lib.crypto;

import at.favre.lib.bytes.Bytes;
import org.junit.Test;

import static org.junit.Assert.assertEquals;

public class SingleStepKdfRefenceValuesTest {

    @Test
    public void compareAgainstRefValueSha256() {
        test(
                SingleStepKdf.fromSha256(),
                Bytes.from("My secret").array(),
                null,
                new byte[16],
                34,
                "5f225b4801843ed861b95f5b0a3afd78473498f0b5cb6d7769e67458e057da8c0311"
        );

        test(
                SingleStepKdf.fromSha256(),
                Bytes.from("another one").array(),
                null,
                Bytes.parseHex("9014bf55dc1e03babb5ca1c1323a1e5b").array(),
                34,
                "4f0a3cf7d52987ccd470d4a8f9d41da9bc6dcf4945c1e522c04fd0c070c397ddb7f4"
        );

        test(
                SingleStepKdf.fromSha256(),
                Bytes.from("e0c42c6524719").array(),
                null,
                Bytes.parseHex("dbebe4f7dde938229f26651e011f7bbd").array(),
                16,
                "d9151c3f36f6980951d84cca75ade71b"
        );

        test(
                SingleStepKdf.fromSha256(),
                Bytes.from("ππππππππ").array(),
                null,
                Bytes.parseHex("676c65eb966200b04a2bb870d7ed20ce").array(),
                165,
                "c5bb681f1a04713ee7be14e0190676773b0ff63561892fac030b18cca38955369cfc32cdd956ef6e2e4301deb61d049a4d82e57a434168bc5ae084e0df15c0a0d8232d7a791088446b66e612753d36649e70a234a360b611baa07e4a6a7c660db2a1b56acba42d6d3d83b3ce51c787c544bb14b1c94b780fab5c0f966efd80f4a71cd4f267f816a3bb1ec8ceddcd810d1665742c8f68767cd9d7f87ad97792edc6896b6518"
        );
    }

    @Test
    public void compareAgainstRefValueHmacSha256() {
        test(
                SingleStepKdf.fromHmacSha256(),
                Bytes.from("My secret").array(),
                null,
                new byte[16],
                34,
                "eba887dca269a550a3882f06f3b1c30058751bc4ec5375e5435e525aeca9782e6311"
        );

        test(
                SingleStepKdf.fromHmacSha256(),
                Bytes.from("another one").array(),
                Bytes.parseHex("ebf4c1e001f26879afc76c7a45ac9541").array(),
                Bytes.parseHex("9014bf55dc1e03babb5ca1c1323a1e5b").array(),
                34,
                "8a6484427e5231642a83e7a01fd410040dda5bf3b3d34ec626a8603ac1a5e2e38f02"
        );

        test(
                SingleStepKdf.fromHmacSha256(),
                Bytes.from("e0c42c6524719").array(),
                null,
                Bytes.parseHex("dbebe4f7dde938229f26651e011f7bbd").array(),
                16,
                "cceb4536d8431c4d91a5c6f061955aac"
        );

        test(
                SingleStepKdf.fromHmacSha256(),
                Bytes.from("ππππππππ").array(),
                Bytes.parseHex("1aab1829c8b7ed941b3dc8359dd1f402").array(),
                Bytes.parseHex("676c65eb966200b04a2bb870d7ed20ce").array(),
                165,
                "2933b1a656efd556c421533e4fab685c4a9c32f15099a357a73a59c6acebb01b9685631d6208992413c2397c58e8020e588cc16f1f1b470a411ab65d6a0503e3728be789e54e313d49bd1edd606757db6c605ed1e346dd6841afd895379ba09dde046a19dce0a8d49b3ed5671d448e141da5f6bcf3aa5313affd8a14784c424b6d5087aa038ab13db398abbd50dfd39d1134dbe88e308373861d7acf1d79b740f717193d5b"
        );
    }

    @Test
    public void compareAgainstRefValueSha512() {
        test(
                SingleStepKdf.fromSha512(),
                Bytes.from("My secret").array(),
                null,
                new byte[16],
                34,
                "8930b01ea45ed7c97c31b5d98a84c48c198c3e5db28241ba9c8417ff1986b53bb4f0"
        );

        test(
                SingleStepKdf.fromSha512(),
                Bytes.from("another one").array(),
                null,
                Bytes.parseHex("9014bf55dc1e03babb5ca1c1323a1e5b").array(),
                34,
                "8c974fe161660b2e02f18f01f93126321218544b728b25fc932fd558f4210cc86fd2"
        );

        test(
                SingleStepKdf.fromSha512(),
                Bytes.from("e0c42c6524719").array(),
                null,
                Bytes.parseHex("dbebe4f7dde938229f26651e011f7bbd").array(),
                16,
                "a7d86c29c01a4db9d38a037be68d0d7e"
        );

        test(
                SingleStepKdf.fromSha512(),
                Bytes.from("ππππππππ").array(),
                null,
                Bytes.parseHex("676c65eb966200b04a2bb870d7ed20ce").array(),
                165,
                "d43a044a9be50d77a6ebc316fce66391600199b95d0ca9bf848e1f86f36263e954cf6f6f30c04270c6eb6c0c67b0e5a7d69e73788562eaa2b35dc4094c28a4d09092d6fe8ea5f1a3426e354ca918c7c634963f62ed992c6494dcc4feac9e3efdd931644cc82d4adb0b3cacf8a074785faf4d3c364ee615b937e6ccb759c1ad302f4b0bf4056e91209e151ea23546f89a66fb8f9b1d00bf1a32f3366ae71b5e953e04f58c5a"
        );
    }

    private void test(SingleStepKdf kdf, byte[] Z, byte[] salt, byte[] otherInfo, int outL, String refHex) {
        byte[] out = kdf.derive(Z, outL, salt, otherInfo);
        assertEquals(Bytes.wrap(out).encodeHex(), refHex);
    }
}
