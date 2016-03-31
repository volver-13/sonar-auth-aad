package org.almrangers.auth.aad;

/**
 * Created by hkamel on 3/27/2016.
 */
public class AadGroup extends DirectoryObject {
    protected String objectId;
    protected String objectType;
    protected String displayName;
    @Override
    public String getObjectId() {
        return objectId;
    }

    @Override
    public void setObjectId(String objectId) {
        this.objectId = objectId;
    }

    @Override
    public String getObjectType() {
        return objectType;
    }

    @Override
    public void setObjectType(String objectType) {
        this.objectType = objectType;
    }

    @Override
    public String getDisplayName() {
        return displayName;
    }

    @Override
    public void setDisplayName(String displayName) {
        this.displayName = displayName;
    }

}
