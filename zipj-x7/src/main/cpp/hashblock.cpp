#include "hashblock.h"
#include <inttypes.h>
#include <jni.h>

// JNI function to call the HashX7 function
JNIEXPORT jbyteArray JNICALL Java_com_hashengineering_crypto_X7_x7_1native
  (JNIEnv *env, jclass cls, jbyteArray input, jlong timestamp)
{
    // Get the input byte array
    jbyte *pInput = (*env)->GetByteArrayElements(env, input, NULL);
    jbyteArray byteArray = NULL;

    if (pInput)
    {
        // Determine the length of the input array
        jsize length = (*env)->GetArrayLength(env, input);

        // Allocate result array (32 bytes)
        jbyte result[32];

        // Call the HashX7 function
        HashX7((uint8_t *)pInput, (uint8_t *)pInput + length, (uint64_t)timestamp, (uint8_t *)result);

        // Create a new byte array to return the result
        byteArray = (*env)->NewByteArray(env, 32);
        if (byteArray)
        {
            (*env)->SetByteArrayRegion(env, byteArray, 0, 32, result);
        }

        // Release the input byte array
        (*env)->ReleaseByteArrayElements(env, input, pInput, JNI_ABORT);
    }
    else
    {
        // Throw NullPointerException if input is null
        jclass e = (*env)->FindClass(env, "java/lang/NullPointerException");
        if (e != NULL)
        {
            (*env)->ThrowNew(env, e, "input is null");
        }
    }
    return byteArray;
}

// Define the JNI method table
static const JNINativeMethod methods[] = {
    { "x7_native", "([BJ)[B", (void *) Java_com_hashengineering_crypto_X7_x7_1native }
};

// JNI OnLoad function
jint JNI_OnLoad(JavaVM *vm, void *reserved) {
    JNIEnv *env;

    if ((*vm)->GetEnv(vm, (void **)&env, JNI_VERSION_1_6) != JNI_OK) {
        return -1;
    }

    jclass cls = (*env)->FindClass(env, "com/hashengineering/crypto/X7");
    if (cls == NULL) {
        return -1;
    }

    int result = (*env)->RegisterNatives(env, cls, methods, sizeof(methods) / sizeof(methods[0]));
    return (result == JNI_OK) ? JNI_VERSION_1_6 : -1;
}
